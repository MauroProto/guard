package report

import (
	"encoding/json"

	"github.com/MauroProto/guard/internal/model"
)

// JSON marshals the report to indented JSON.
func JSON(r *model.Report) ([]byte, error) {
	clone := *r
	clone.Normalize()
	if clone.Findings == nil {
		clone.Findings = []model.Finding{}
	}
	return json.MarshalIndent(&clone, "", "  ")
}
