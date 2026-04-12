package pnpm

import (
	"os"
	"path/filepath"

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
	out, err := yaml.Marshal(ws)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}
