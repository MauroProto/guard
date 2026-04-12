package osv

import "context"

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

// TODO: implement an HTTP client against https://api.osv.dev/v1/query
// The implementation should:
// 1. POST to https://api.osv.dev/v1/query with {package:{name,ecosystem}, version}
// 2. Parse the response into []Advisory
// 3. Support offline mode (return empty results with a warning)
// 4. Cache results in ${XDG_CACHE_HOME}/guard/osv/
