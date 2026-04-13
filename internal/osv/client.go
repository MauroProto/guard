package osv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/cache"
)

// Query represents a vulnerability lookup request.
type Query struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// Advisory represents a known vulnerability.
type Advisory struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Summary  string `json:"summary"`
}

// Client queries the OSV database for known vulnerabilities.
type Client interface {
	Query(ctx context.Context, q Query) ([]Advisory, error)
}

// HTTPClient is a cache-aware OSV client.
type HTTPClient struct {
	BaseURL  string
	Client   *http.Client
	CacheDir string
	Offline  bool
}

// NewClient returns a cache-aware OSV HTTP client.
func NewClient(root string, offline bool) Client {
	return &HTTPClient{
		BaseURL:  "https://api.osv.dev/v1/query",
		Client:   &http.Client{Timeout: 5 * time.Second},
		CacheDir: cache.Dir(root, "osv"),
		Offline:  offline,
	}
}

func (c *HTTPClient) Query(ctx context.Context, q Query) ([]Advisory, error) {
	cachePath := filepath.Join(c.CacheDir, cacheKey(q)+".json")
	if c.Offline {
		return parseCachedOSV(cachePath)
	}

	payload, err := json.Marshal(map[string]any{
		"package": map[string]string{
			"name":      q.Name,
			"ecosystem": q.Ecosystem,
		},
		"version": q.Version,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return parseCachedOSV(cachePath)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseCachedOSV(cachePath)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return parseCachedOSV(cachePath)
	}
	_ = os.MkdirAll(c.CacheDir, 0o755)
	_ = os.WriteFile(cachePath, body, 0o644)

	return parseOSVResponse(body), nil
}

type osvResponse struct {
	Vulns []struct {
		ID               string `json:"id"`
		Summary          string `json:"summary"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		Severity []struct {
			Score string `json:"score"`
		} `json:"severity"`
	} `json:"vulns"`
}

func parseCachedOSV(path string) ([]Advisory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return parseOSVResponse(b), nil
}

func parseOSVResponse(b []byte) []Advisory {
	var parsed osvResponse
	if err := json.Unmarshal(b, &parsed); err != nil {
		return nil
	}
	advisories := make([]Advisory, 0, len(parsed.Vulns))
	for _, vuln := range parsed.Vulns {
		advisories = append(advisories, Advisory{
			ID:       vuln.ID,
			Severity: normalizeSeverity(vuln.DatabaseSpecific.Severity, vuln.Severity),
			Summary:  vuln.Summary,
		})
	}
	return advisories
}

func normalizeSeverity(dbSeverity string, scores []struct {
	Score string `json:"score"`
}) string {
	if dbSeverity != "" {
		return strings.ToLower(dbSeverity)
	}
	if len(scores) == 0 || scores[0].Score == "" {
		return "high"
	}
	score := scores[0].Score
	if idx := strings.Index(score, "/"); idx >= 0 {
		score = score[:idx]
	}
	value, err := strconv.ParseFloat(score, 64)
	if err != nil {
		return "high"
	}
	switch {
	case value >= 9:
		return "critical"
	case value >= 7:
		return "high"
	case value >= 4:
		return "medium"
	default:
		return "low"
	}
}

func cacheKey(q Query) string {
	sum := sha256.Sum256([]byte(q.Ecosystem + ":" + q.Name + "@" + q.Version))
	return hex.EncodeToString(sum[:])
}
