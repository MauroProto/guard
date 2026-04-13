package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHTTPClientQueryCachesAndReadsOffline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vulns":[{"id":"OSV-1","summary":"test vuln","database_specific":{"severity":"HIGH"}}]}`))
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client := &HTTPClient{
		BaseURL:  server.URL,
		Client:   server.Client(),
		CacheDir: cacheDir,
	}

	advisories, err := client.Query(context.Background(), Query{Name: "left-pad", Version: "1.0.0", Ecosystem: "npm"})
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(advisories) != 1 || advisories[0].ID != "OSV-1" {
		t.Fatalf("unexpected advisories: %+v", advisories)
	}

	offline := &HTTPClient{
		BaseURL:  server.URL,
		Client:   server.Client(),
		CacheDir: cacheDir,
		Offline:  true,
	}
	cached, err := offline.Query(context.Background(), Query{Name: "left-pad", Version: "1.0.0", Ecosystem: "npm"})
	if err != nil {
		t.Fatalf("offline query failed: %v", err)
	}
	if len(cached) != 1 || cached[0].ID != "OSV-1" {
		t.Fatalf("unexpected cached advisories: %+v", cached)
	}
}

func TestHTTPClientOfflineWithoutCacheReturnsEmpty(t *testing.T) {
	client := &HTTPClient{
		CacheDir: t.TempDir(),
		Offline:  true,
	}
	advisories, err := client.Query(context.Background(), Query{Name: "left-pad", Version: "1.0.0", Ecosystem: "npm"})
	if err != nil {
		t.Fatalf("offline query failed: %v", err)
	}
	if len(advisories) != 0 {
		t.Fatalf("expected no advisories, got %+v", advisories)
	}
}

func TestCacheKeyStable(t *testing.T) {
	first := cacheKey(Query{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"})
	second := cacheKey(Query{Name: "pkg", Version: "1.0.0", Ecosystem: "npm"})
	if first != second {
		t.Fatalf("expected stable cache key, got %s and %s", first, second)
	}
	if _, err := os.Stat(filepath.Dir(filepath.Join(t.TempDir(), first))); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected stat error: %v", err)
	}
}
