package yamlutil

import (
	"bytes"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadDocument reads a YAML document from disk.
func LoadDocument(path string) (*yaml.Node, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc := &yaml.Node{}
	if err := yaml.Unmarshal(b, doc); err != nil {
		return nil, err
	}
	EnsureDocument(doc)
	return doc, nil
}

// NewDocument marshals a value and returns it as a YAML document node.
func NewDocument(v any) (*yaml.Node, error) {
	b, err := yaml.Marshal(v)
	if err != nil {
		return nil, err
	}
	doc := &yaml.Node{}
	if err := yaml.Unmarshal(b, doc); err != nil {
		return nil, err
	}
	EnsureDocument(doc)
	return doc, nil
}

// EnsureDocument normalizes a YAML document node.
func EnsureDocument(doc *yaml.Node) {
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
		}}
	}
}

// MergeDocuments overlays src onto dst, preserving unknown keys already present in dst.
func MergeDocuments(dst, src *yaml.Node) {
	EnsureDocument(dst)
	EnsureDocument(src)
	mergeNode(dst.Content[0], src.Content[0])
}

func mergeNode(dst, src *yaml.Node) {
	if dst == nil || src == nil {
		return
	}
	if src.Kind == yaml.MappingNode {
		if dst.Kind != yaml.MappingNode {
			*dst = *DeepCopy(src)
			return
		}
		for i := 0; i < len(src.Content); i += 2 {
			srcKey := src.Content[i]
			srcVal := src.Content[i+1]
			if dstVal := MappingValue(dst, srcKey.Value); dstVal != nil {
				mergeNode(dstVal, srcVal)
				continue
			}
			dst.Content = append(dst.Content, DeepCopy(srcKey), DeepCopy(srcVal))
		}
		return
	}
	*dst = *DeepCopy(src)
}

// MappingValue returns a mapping value node by key.
func MappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// DeepCopy clones a YAML node recursively.
func DeepCopy(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	clone := *node
	if len(node.Content) > 0 {
		clone.Content = make([]*yaml.Node, len(node.Content))
		for i, child := range node.Content {
			clone.Content[i] = DeepCopy(child)
		}
	}
	return &clone
}

// MarshalDocument renders a YAML document with stable indentation.
func MarshalDocument(doc *yaml.Node) ([]byte, error) {
	EnsureDocument(doc)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		_ = enc.Close()
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
