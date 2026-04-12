package config

import "gopkg.in/yaml.v3"

// MarshalYAML serializes a Config to YAML bytes.
func MarshalYAML(cfg *Config) ([]byte, error) {
	return yaml.Marshal(cfg)
}
