package npm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	Name              string
	Version           string
	TarballURL        string
	Integrity         string
	RegistryHost      string
	Publisher         string
	Provenance        bool
	TrustedPublishing bool
	HasSignatures     bool
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
		return loadCachedMetadataOr(cachePath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return loadCachedMetadataOr(cachePath, fmt.Errorf("registry returned %s for %s@%s", resp.Status, name, version))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return loadCachedMetadataOr(cachePath, err)
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

func loadCachedMetadataOr(path string, fallback error) (*VersionMetadata, error) {
	meta, err := loadCachedMetadata(path)
	if err == nil {
		return meta, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, fallback
	}
	return nil, err
}

func parseMetadata(b []byte) (*VersionMetadata, error) {
	var payload struct {
		Name              string `json:"name"`
		Version           string `json:"version"`
		Provenance        bool   `json:"provenance"`
		TrustedPublishing bool   `json:"trustedPublishing"`
		Dist              struct {
			Tarball    string `json:"tarball"`
			Integrity  string `json:"integrity"`
			Provenance bool   `json:"provenance"`
			Signatures []struct {
				KeyID string `json:"keyid"`
			} `json:"signatures"`
		} `json:"dist"`
		NPMUser struct {
			Name string `json:"name"`
		} `json:"_npmUser"`
	}
	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, err
	}
	registryHost := ""
	if payload.Dist.Tarball != "" {
		if parsed, err := url.Parse(payload.Dist.Tarball); err == nil {
			registryHost = parsed.Host
		}
	}
	return &VersionMetadata{
		Name:              payload.Name,
		Version:           payload.Version,
		TarballURL:        payload.Dist.Tarball,
		Integrity:         payload.Dist.Integrity,
		RegistryHost:      registryHost,
		Publisher:         payload.NPMUser.Name,
		Provenance:        payload.Provenance || payload.Dist.Provenance,
		TrustedPublishing: payload.TrustedPublishing,
		HasSignatures:     len(payload.Dist.Signatures) > 0,
	}, nil
}

func cacheKey(name, version string) string {
	sum := sha256.Sum256([]byte(name + "@" + version))
	return hex.EncodeToString(sum[:])
}
