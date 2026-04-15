package diff

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/cache"
	"github.com/MauroProto/guard/internal/npm"
)

// FetchPackageContents downloads and expands a package tarball from the registry.
func FetchPackageContents(ctx context.Context, root, name, version string) (*PackageContents, error) {
	registry := npm.NewClient(root)
	meta, err := registry.Version(ctx, name, version)
	if err != nil {
		return nil, fmt.Errorf("load registry metadata for %s@%s: %w", name, version, err)
	}

	cacheDir := cache.Dir(root, "diff")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, err
	}

	tarballPath := filepath.Join(cacheDir, tarballCacheKey(name, version)+".tgz")
	if _, err := os.Stat(tarballPath); os.IsNotExist(err) {
		if err := downloadTarball(ctx, meta.TarballURL, tarballPath); err != nil {
			return nil, err
		}
	}

	if meta.Integrity != "" {
		if err := verifyIntegrity(tarballPath, meta.Integrity); err != nil {
			return nil, err
		}
	}

	return extractTarball(tarballPath)
}

// LoadLocalContents reads package contents from a local directory.
func LoadLocalContents(dir string) (*PackageContents, error) {
	pc := &PackageContents{
		Files: make(map[string][]byte),
	}

	pkgPath := filepath.Join(dir, "package.json")
	if b, err := os.ReadFile(pkgPath); err == nil {
		var pkg map[string]any
		if json.Unmarshal(b, &pkg) == nil {
			pc.PackageJSON = pkg
		}
	}

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

func downloadTarball(ctx context.Context, tarballURL, dest string) error {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tarballURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download tarball: unexpected status %s", resp.Status)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func verifyIntegrity(path, integrity string) error {
	parts := strings.SplitN(integrity, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("unsupported integrity format %q", integrity)
	}
	expected, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var hasher hash.Hash
	switch parts[0] {
	case "sha512":
		hasher = sha512.New()
	case "sha256":
		hasher = sha256.New()
	default:
		return fmt.Errorf("unsupported integrity algorithm %q", parts[0])
	}

	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}

	if !bytesEqual(hasher.Sum(nil), expected) {
		return fmt.Errorf("tarball integrity mismatch for %s", filepath.Base(path))
	}
	return nil
}

func extractTarball(path string) (*PackageContents, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	pc := &PackageContents{
		Files: make(map[string][]byte),
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		name := strings.TrimPrefix(filepath.ToSlash(hdr.Name), "package/")
		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		pc.Files[name] = content
		pc.FileList = append(pc.FileList, name)
		if name == "package.json" {
			var pkg map[string]any
			if json.Unmarshal(content, &pkg) == nil {
				pc.PackageJSON = pkg
			}
		}
	}

	sort.Strings(pc.FileList)
	return pc, nil
}

func tarballCacheKey(name, version string) string {
	sum := sha256.Sum256([]byte(name + "@" + version))
	return fmt.Sprintf("%x", sum[:])
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
