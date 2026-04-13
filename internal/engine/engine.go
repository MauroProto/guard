package engine

import (
	"time"

	"github.com/MauroProto/guard/internal/model"
)

// Version is the current Guard release.
var Version = "dev"

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
