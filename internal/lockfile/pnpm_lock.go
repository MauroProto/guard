package lockfile

import (
	"os"
	"sort"
	"strings"

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
	Dependencies         map[string]any `yaml:"dependencies"`
	DevDependencies      map[string]any `yaml:"devDependencies"`
	OptionalDependencies map[string]any `yaml:"optionalDependencies"`
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
	return Parse(b)
}

func Parse(b []byte) (*PNPM, error) {
	var lock PNPM
	if err := yaml.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	return &lock, nil
}

type PackageRef struct {
	Importer string
	Version  string
}

func ResolvePackageRefs(lock *PNPM, pkg string) []PackageRef {
	if lock == nil {
		return nil
	}
	seen := map[string]bool{}
	var refs []PackageRef

	addRef := func(importer, version string) {
		key := importer + "\x00" + version
		if seen[key] {
			return
		}
		seen[key] = true
		refs = append(refs, PackageRef{Importer: importer, Version: version})
	}

	for importer, data := range lock.Importers {
		for _, deps := range []map[string]any{data.Dependencies, data.DevDependencies, data.OptionalDependencies} {
			version, ok := resolveImporterDependencyVersion(deps, pkg)
			if ok {
				addRef(importer, version)
			}
		}
	}

	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Importer == refs[j].Importer {
			return refs[i].Version < refs[j].Version
		}
		return refs[i].Importer < refs[j].Importer
	})
	return refs
}

func resolveImporterDependencyVersion(deps map[string]any, pkg string) (string, bool) {
	if deps == nil {
		return "", false
	}
	raw, ok := deps[pkg]
	if !ok {
		return "", false
	}
	switch value := raw.(type) {
	case string:
		return strings.TrimPrefix(value, "link:"), value != ""
	case map[string]any:
		if version, ok := value["version"].(string); ok {
			return strings.TrimPrefix(version, "link:"), version != ""
		}
	case map[any]any:
		if version, ok := value["version"].(string); ok {
			return strings.TrimPrefix(version, "link:"), version != ""
		}
	}
	return "", false
}
