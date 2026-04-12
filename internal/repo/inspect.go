package repo

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// PackageJSON holds the fields Guard cares about.
type PackageJSON struct {
	Name           string            `json:"name"`
	PackageManager string            `json:"packageManager"`
	Engines        map[string]string `json:"engines"`
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
	WorkflowFiles    []string
}

// Inspect reads the repo root and returns a State snapshot.
func Inspect(root string) (*State, error) {
	s := &State{Root: root}

	if b, err := os.ReadFile(filepath.Join(root, "package.json")); err == nil {
		s.HasPackageJSON = true
		var pkg PackageJSON
		if json.Unmarshal(b, &pkg) == nil {
			s.PackageJSON = &pkg
		}
	}

	if _, err := os.Stat(filepath.Join(root, "pnpm-lock.yaml")); err == nil {
		s.HasPNPMLockfile = true
	}
	if _, err := os.Stat(filepath.Join(root, "pnpm-workspace.yaml")); err == nil {
		s.HasPNPMWorkspace = true
	}
	if _, err := os.Stat(filepath.Join(root, ".guard", "policy.yaml")); err == nil {
		s.HasGuardPolicy = true
	}

	// CODEOWNERS can be in root, docs/, or .github/
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

	workflowRoot := filepath.Join(root, ".github", "workflows")
	_ = filepath.Walk(workflowRoot, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".yml" || ext == ".yaml" {
				s.WorkflowFiles = append(s.WorkflowFiles, path)
			}
		}
		return nil
	})

	return s, nil
}
