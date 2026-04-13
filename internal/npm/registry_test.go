package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPRegistryVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"left-pad","version":"1.0.0","dist":{"tarball":"https://example.com/left-pad.tgz","integrity":"sha512-abc"}}`))
	}))
	defer server.Close()

	registry := &HTTPRegistry{
		BaseURL:  server.URL,
		Client:   server.Client(),
		CacheDir: t.TempDir(),
	}
	meta, err := registry.Version(context.Background(), "left-pad", "1.0.0")
	if err != nil {
		t.Fatalf("registry query failed: %v", err)
	}
	if meta.Name != "left-pad" || meta.Version != "1.0.0" {
		t.Fatalf("unexpected metadata: %+v", meta)
	}
	if meta.TarballURL == "" || meta.Integrity == "" {
		t.Fatalf("expected tarball metadata, got %+v", meta)
	}
}

func TestHTTPRegistryVersionNotFoundWithoutCacheReturnsRegistryError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	registry := &HTTPRegistry{
		BaseURL:  server.URL,
		Client:   server.Client(),
		CacheDir: t.TempDir(),
	}
	_, err := registry.Version(context.Background(), "missing-pkg", "9.9.9")
	if err == nil {
		t.Fatal("expected registry query to fail")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("expected error to mention 404, got %v", err)
	}
	if strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("expected registry error, got cache ENOENT: %v", err)
	}
}
