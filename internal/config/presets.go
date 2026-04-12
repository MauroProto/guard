package config

import "fmt"

// Preset returns a Config tuned for the given preset name.
func Preset(name string) (*Config, error) {
	base := Default()
	switch name {
	case "balanced":
		// default values are already balanced
	case "strict":
		base.PNPM.MinimumReleaseAgeMinutes = 4320
		base.Enforcement.FailOn = "medium"
	case "local":
		base.PNPM.MinimumReleaseAgeMinutes = 60
		base.Enforcement.FailOn = "critical"
	default:
		return nil, fmt.Errorf("unknown preset: %s (valid: strict, balanced, local)", name)
	}
	return base, nil
}
