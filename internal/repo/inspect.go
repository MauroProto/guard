package repo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/MauroProto/guard/internal/pnpm"
)

// PackageJSON holds the fields Guard cares about.
type PackageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	PackageManager       string            `json:"packageManager"`
	Engines              map[string]string `json:"engines"`
	Scripts              map[string]string `json:"scripts"`
	Private              bool              `json:"private"`
	PublishConfig        map[string]any    `json:"publishConfig"`
	Bin                  any               `json:"bin"`
	Dependencies         map[string]any    `json:"dependencies"`
	DevDependencies      map[string]any    `json:"devDependencies"`
	PeerDependencies     map[string]any    `json:"peerDependencies"`
	OptionalDependencies map[string]any    `json:"optionalDependencies"`
}

// PackageState describes a discovered package.json in the repository.
type PackageState struct {
	Dir         string
	RelDir      string
	RelFile     string
	PackageJSON *PackageJSON
}

// State describes what Guard found in the repository root.
type State struct {
	Root             string
	HasPackageJSON   bool
	HasPNPMLockfile  bool
	HasPNPMWorkspace bool
	HasGuardPolicy   bool
	HasCodeowners    bool
	PackageJSON      *PackageJSON
	Packages         []PackageState
	WorkflowFiles    []string
}

// Inspect reads the repo root and returns a State snapshot.
func Inspect(root string, workflowPaths []string) (*State, error) {
	s := &State{Root: root}
	seenPackages := map[string]bool{}

	if pkg, err := loadPackage(root, root); err == nil {
		s.HasPackageJSON = true
		s.PackageJSON = pkg.PackageJSON
		s.Packages = append(s.Packages, *pkg)
		seenPackages[pkg.RelDir] = true
	}

	if _, err := os.Stat(filepath.Join(root, "pnpm-lock.yaml")); err == nil {
		s.HasPNPMLockfile = true
	}
	if _, err := os.Stat(filepath.Join(root, "pnpm-workspace.yaml")); err == nil {
		s.HasPNPMWorkspace = true
		if ws, loadErr := pnpm.Load(root); loadErr == nil {
			dirs, resolveErr := pnpm.ResolvePackageDirs(root, ws.Packages)
			if resolveErr == nil {
				for _, dir := range dirs {
					pkg, pkgErr := loadPackage(root, dir)
					if pkgErr != nil || seenPackages[pkg.RelDir] {
						continue
					}
					seenPackages[pkg.RelDir] = true
					s.Packages = append(s.Packages, *pkg)
				}
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".guard", "policy.yaml")); err == nil {
		s.HasGuardPolicy = true
	}

	for _, p := range []string{
		filepath.Join(root, ".github", "CODEOWNERS"),
		filepath.Join(root, "CODEOWNERS"),
		filepath.Join(root, "docs", "CODEOWNERS"),
	} {
		if _, err := os.Stat(p); err == nil {
			s.HasCodeowners = true
			break
		}
	}

	if len(workflowPaths) == 0 {
		workflowPaths = []string{".github/workflows"}
	}
	for _, rel := range workflowPaths {
		workflowRoot := filepath.Join(root, filepath.FromSlash(rel))
		_ = filepath.Walk(workflowRoot, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				ext := filepath.Ext(path)
				if ext == ".yml" || ext == ".yaml" {
					s.WorkflowFiles = append(s.WorkflowFiles, path)
				}
			}
			return nil
		})
	}

	sort.Slice(s.Packages, func(i, j int) bool {
		return s.Packages[i].RelDir < s.Packages[j].RelDir
	})
	sort.Strings(s.WorkflowFiles)

	return s, nil
}

func loadPackage(root, dir string) (*PackageState, error) {
	path := filepath.Join(dir, "package.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pkg PackageJSON
	if err := json.Unmarshal(b, &pkg); err != nil {
		return nil, err
	}
	relDir, err := filepath.Rel(root, dir)
	if err != nil {
		relDir = dir
	}
	relDir = filepath.ToSlash(relDir)
	if relDir == "" {
		relDir = "."
	}
	relFile := "package.json"
	if relDir != "." {
		relFile = filepath.ToSlash(filepath.Join(relDir, "package.json"))
	}
	return &PackageState{
		Dir:         dir,
		RelDir:      relDir,
		RelFile:     relFile,
		PackageJSON: &pkg,
	}, nil
}
