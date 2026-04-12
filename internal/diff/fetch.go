package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// FetchPackageContents downloads and expands a package tarball from the registry.
// TODO: implement actual tarball download from npm registry.
// The implementation should:
// 1. Call registry.Version(ctx, name, version) to get tarball URL
// 2. Download the tarball to cache directory
// 3. Extract and return PackageContents
func FetchPackageContents(ctx context.Context, name, version string) (*PackageContents, error) {
	_ = ctx
	return nil, fmt.Errorf("tarball download not yet implemented for %s@%s — use --from-dir/--to-dir for local comparison", name, version)
}

// LoadLocalContents reads package contents from a local directory.
func LoadLocalContents(dir string) (*PackageContents, error) {
	pc := &PackageContents{
		Files: make(map[string][]byte),
	}

	// Read package.json if it exists
	pkgPath := filepath.Join(dir, "package.json")
	if b, err := os.ReadFile(pkgPath); err == nil {
		var pkg map[string]any
		if json.Unmarshal(b, &pkg) == nil {
			pc.PackageJSON = pkg
		}
	}

	// Walk directory and collect files
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "node_modules" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath)

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		pc.Files[relPath] = content
		pc.FileList = append(pc.FileList, relPath)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(pc.FileList)
	return pc, nil
}
