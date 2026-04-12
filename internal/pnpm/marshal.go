package pnpm

import "gopkg.in/yaml.v3"

// MarshalYAML serializes a Workspace to YAML bytes.
func MarshalYAML(ws *Workspace) ([]byte, error) {
	return yaml.Marshal(ws)
}
