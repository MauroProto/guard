package npm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/MauroProto/guard/internal/cache"
)

// VersionMetadata holds registry information about a specific package version.
type VersionMetadata struct {
	Name       string
	Version    string
	TarballURL string
	Integrity  string
}

// Registry provides access to npm package metadata.
type Registry interface {
	Version(ctx context.Context, name, version string) (*VersionMetadata, error)
}

// HTTPRegistry is a cache-aware npm registry client.
type HTTPRegistry struct {
	BaseURL  string
	Client   *http.Client
	CacheDir string
}

// NewClient returns the default npm registry client.
func NewClient(root string) Registry {
	return &HTTPRegistry{
		BaseURL:  "https://registry.npmjs.org",
		Client:   &http.Client{Timeout: 5 * time.Second},
		CacheDir: cache.Dir(root, "npm"),
	}
}

func (r *HTTPRegistry) Version(ctx context.Context, name, version string) (*VersionMetadata, error) {
	cachePath := filepath.Join(r.CacheDir, cacheKey(name, version)+".json")
	endpoint := r.BaseURL + "/" + url.PathEscape(name) + "/" + url.PathEscape(version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return loadCachedMetadata(cachePath)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return loadCachedMetadata(cachePath)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return loadCachedMetadata(cachePath)
	}
	_ = os.MkdirAll(r.CacheDir, 0o755)
	_ = os.WriteFile(cachePath, body, 0o644)
	return parseMetadata(body)
}

func loadCachedMetadata(path string) (*VersionMetadata, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseMetadata(b)
}

func parseMetadata(b []byte) (*VersionMetadata, error) {
	var payload struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Dist    struct {
			Tarball   string `json:"tarball"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, err
	}
	return &VersionMetadata{
		Name:       payload.Name,
		Version:    payload.Version,
		TarballURL: payload.Dist.Tarball,
		Integrity:  payload.Dist.Integrity,
	}, nil
}

func cacheKey(name, version string) string {
	sum := sha256.Sum256([]byte(name + "@" + version))
	return hex.EncodeToString(sum[:])
}
