package cache

import (
	"os"
	"path/filepath"
)

// Dir returns the cache directory for the given feature.
func Dir(root, feature string) string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "guard", feature)
	}
	return filepath.Join(root, ".guard", "cache", feature)
}
