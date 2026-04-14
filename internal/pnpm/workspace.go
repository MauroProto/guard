package pnpm

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MauroProto/guard/internal/yamlutil"
	"gopkg.in/yaml.v3"
)

const WorkspaceFile = "pnpm-workspace.yaml"

// Workspace represents the pnpm-workspace.yaml configuration.
type Workspace struct {
	Packages                     []string        `yaml:"packages,omitempty"`
	MinimumReleaseAge            int             `yaml:"minimumReleaseAge,omitempty"`
	MinimumReleaseAgeExclude     []string        `yaml:"minimumReleaseAgeExclude,omitempty"`
	TrustPolicy                  string          `yaml:"trustPolicy,omitempty"`
	TrustPolicyIgnoreAfter       int             `yaml:"trustPolicyIgnoreAfter,omitempty"`
	BlockExoticSubdeps           bool            `yaml:"blockExoticSubdeps,omitempty"`
	StrictDepBuilds              bool            `yaml:"strictDepBuilds,omitempty"`
	AllowBuilds                  map[string]bool `yaml:"allowBuilds,omitempty"`
	PackageManagerStrict         bool            `yaml:"packageManagerStrict,omitempty"`
	ManagePackageManagerVersions bool            `yaml:"managePackageManagerVersions,omitempty"`
}

// DefaultWorkspace returns a hardened pnpm-workspace.yaml configuration.
func DefaultWorkspace() *Workspace {
	return &Workspace{
		Packages:                     []string{"packages/*"},
		MinimumReleaseAge:            1440,
		TrustPolicy:                  "no-downgrade",
		TrustPolicyIgnoreAfter:       43200,
		BlockExoticSubdeps:           true,
		StrictDepBuilds:              true,
		AllowBuilds:                  map[string]bool{},
		PackageManagerStrict:         true,
		ManagePackageManagerVersions: true,
	}
}

// Load reads pnpm-workspace.yaml from the given root.
func Load(root string) (*Workspace, error) {
	path := filepath.Join(root, WorkspaceFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ws Workspace
	if err := yaml.Unmarshal(b, &ws); err != nil {
		return nil, err
	}
	if ws.AllowBuilds == nil {
		ws.AllowBuilds = map[string]bool{}
	}
	return &ws, nil
}

// Save writes pnpm-workspace.yaml to disk.
func Save(root string, ws *Workspace) error {
	path := filepath.Join(root, WorkspaceFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	desired, err := yamlutil.NewDocument(ws)
	if err != nil {
		return err
	}
	doc := desired
	if existing, err := yamlutil.LoadDocument(path); err == nil {
		yamlutil.MergeDocuments(existing, desired)
		doc = existing
	} else if !os.IsNotExist(err) {
		return err
	}
	out, err := yamlutil.MarshalDocument(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// ResolvePackageDirs expands workspace patterns into an ordered set of package directories.
func ResolvePackageDirs(root string, patterns []string) ([]string, error) {
	included := map[string]bool{}
	var ordered []string

	for _, pattern := range patterns {
		exclude := strings.HasPrefix(pattern, "!")
		if exclude {
			pattern = strings.TrimPrefix(pattern, "!")
		}
		pattern = filepath.Clean(filepath.FromSlash(pattern))
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			return nil, err
		}
		sort.Strings(matches)
		for _, match := range matches {
			info, err := os.Stat(match)
			if err != nil {
				continue
			}
			dir := match
			if !info.IsDir() {
				dir = filepath.Dir(match)
			}
			rel, err := filepath.Rel(root, dir)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			if exclude {
				delete(included, dir)
				continue
			}
			if included[dir] {
				continue
			}
			included[dir] = true
			ordered = append(ordered, dir)
		}
	}

	result := ordered[:0]
	for _, dir := range ordered {
		if included[dir] {
			result = append(result, dir)
		}
	}
	return result, nil
}
