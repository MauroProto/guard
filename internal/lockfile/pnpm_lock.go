package lockfile

import (
	"os"

	"gopkg.in/yaml.v3"
)

// PNPM represents the structure of pnpm-lock.yaml.
type PNPM struct {
	LockfileVersion any                    `yaml:"lockfileVersion"`
	Importers       map[string]Importer    `yaml:"importers"`
	Packages        map[string]PackageNode `yaml:"packages"`
}

// Importer represents a workspace importer entry.
type Importer struct {
	Dependencies    map[string]any `yaml:"dependencies"`
	DevDependencies map[string]any `yaml:"devDependencies"`
}

// PackageNode represents a resolved package in the lockfile.
type PackageNode struct {
	Resolution map[string]any `yaml:"resolution"`
}

// Load reads and parses a pnpm lockfile.
func Load(path string) (*PNPM, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock PNPM
	if err := yaml.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	return &lock, nil
}
