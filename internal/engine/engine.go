package engine

import (
	"time"

	"guard/internal/model"
)

// Version is the current Guard release.
const Version = "0.1.0"

// NewReport creates a blank report for the given root.
func NewReport(root string) *model.Report {
	return &model.Report{
		Tool:      "guard",
		Version:   Version,
		Root:      root,
		Timestamp: time.Now().UTC(),
		Decision:  "pass",
	}
}
