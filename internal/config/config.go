package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const DefaultPolicyPath = ".guard/policy.yaml"

type Config struct {
	Version     int         `yaml:"version"`
	Project     Project     `yaml:"project"`
	Enforcement Enforcement `yaml:"enforcement"`
	PNPM        PNPM        `yaml:"pnpm"`
	GitHub      GitHub      `yaml:"github"`
	OSV         OSV         `yaml:"osv"`
	Diff        Diff        `yaml:"diff"`
	Exceptions  Exceptions  `yaml:"exceptions"`
}

type Project struct {
	Name           string `yaml:"name"`
	Ecosystem      string `yaml:"ecosystem"`
	PackageManager string `yaml:"packageManager"`
}

type Enforcement struct {
	FailOn         string   `yaml:"failOn"`
	OutputDefaults []string `yaml:"outputDefaults"`
}

type PNPM struct {
	MinimumReleaseAgeMinutes      int             `yaml:"minimumReleaseAgeMinutes"`
	MinimumReleaseAgeExclude      []string        `yaml:"minimumReleaseAgeExclude"`
	TrustPolicy                   string          `yaml:"trustPolicy"`
	TrustPolicyIgnoreAfterMinutes int             `yaml:"trustPolicyIgnoreAfterMinutes"`
	BlockExoticSubdeps            bool            `yaml:"blockExoticSubdeps"`
	StrictDepBuilds               bool            `yaml:"strictDepBuilds"`
	AllowBuilds                   map[string]bool `yaml:"allowBuilds"`
	RequireLockfile               bool            `yaml:"requireLockfile"`
	RequireFrozenLockfileInCI     bool            `yaml:"requireFrozenLockfileInCI"`
	RequirePackageManagerField    bool            `yaml:"requirePackageManagerField"`
	RequireNodeEngine             bool            `yaml:"requireNodeEngine"`
}

type GitHub struct {
	RequirePinnedActions          bool     `yaml:"requirePinnedActions"`
	RequireReadOnlyDefaultToken   bool     `yaml:"requireReadOnlyDefaultToken"`
	RequireCodeownersForWorkflows bool     `yaml:"requireCodeownersForWorkflows"`
	WorkflowPaths                 []string `yaml:"workflowPaths"`
}

type OSV struct {
	Enabled        bool   `yaml:"enabled"`
	FailOnSeverity string `yaml:"failOnSeverity"`
}

type Diff struct {
	Enabled        bool     `yaml:"enabled"`
	FailOnSignals  []string `yaml:"failOnSignals"`
	SuspiciousAPIs []string `yaml:"suspiciousApis"`
}

type Exceptions struct {
	Rules    []RuleException    `yaml:"rules"`
	Packages []PackageException `yaml:"packages"`
}

type RuleException struct {
	ID        string `yaml:"id"`
	Reason    string `yaml:"reason"`
	ExpiresAt string `yaml:"expiresAt"`
}

type PackageException struct {
	Name      string   `yaml:"name"`
	Reason    string   `yaml:"reason"`
	Allows    []string `yaml:"allows"`
	ExpiresAt string   `yaml:"expiresAt"`
}

// Default returns a Config with balanced-preset values.
func Default() *Config {
	return &Config{
		Version: 1,
		Project: Project{
			Ecosystem:      "node",
			PackageManager: "pnpm",
		},
		Enforcement: Enforcement{
			FailOn:         "high",
			OutputDefaults: []string{"terminal", "json"},
		},
		PNPM: PNPM{
			MinimumReleaseAgeMinutes:      1440,
			MinimumReleaseAgeExclude:      []string{},
			TrustPolicy:                   "no-downgrade",
			TrustPolicyIgnoreAfterMinutes: 43200,
			BlockExoticSubdeps:            true,
			StrictDepBuilds:               true,
			AllowBuilds:                   map[string]bool{},
			RequireLockfile:               true,
			RequireFrozenLockfileInCI:     true,
			RequirePackageManagerField:    true,
			RequireNodeEngine:             true,
		},
		GitHub: GitHub{
			RequirePinnedActions:          true,
			RequireReadOnlyDefaultToken:   true,
			RequireCodeownersForWorkflows: true,
			WorkflowPaths:                []string{".github/workflows"},
		},
		OSV: OSV{
			Enabled:        true,
			FailOnSeverity: "high",
		},
		Diff: Diff{
			Enabled: true,
			FailOnSignals: []string{
				"install_script_added",
				"remote_url_added",
			},
			SuspiciousAPIs: []string{
				"child_process.exec",
				"child_process.spawn",
				"eval",
				"Function",
				"vm.Script",
			},
		},
	}
}

// Load reads and parses a policy file. Falls back to defaults on missing file.
func Load(root, path string) (*Config, error) {
	if path == "" {
		path = filepath.Join(root, DefaultPolicyPath)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, err
	}
	if cfg.Version != 1 {
		return nil, errors.New("unsupported config version")
	}
	return cfg, nil
}

// Save writes a Config to disk as YAML.
func Save(root, path string, cfg *Config) error {
	if path == "" {
		path = filepath.Join(root, DefaultPolicyPath)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}
