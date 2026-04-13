package npm

import "regexp"

var packageNamePattern = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

// ValidPackageName reports whether a package name is safe to pass to local tooling.
func ValidPackageName(name string) bool {
	return packageNamePattern.MatchString(name)
}
