package npm

import "context"

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

// TODO: implement npm registry metadata client for diff mode.
// The implementation should:
// 1. GET https://registry.npmjs.org/{name}/{version}
// 2. Extract dist.tarball and dist.integrity
// 3. Support scoped packages (@scope/name)
// 4. Cache responses in ${XDG_CACHE_HOME}/guard/npm/
