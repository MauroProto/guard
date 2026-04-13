package report

import (
	"encoding/json"

	"github.com/MauroProto/guard/internal/model"
)

// JSON marshals the report to indented JSON.
func JSON(r *model.Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
