package cli

import (
	"os"

	"github.com/MauroProto/guard/internal/baseline"
	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/model"
)

func applyBaselineToReport(root string, cfg *config.Config, rep *model.Report, ignore bool) {
	if ignore || cfg == nil || rep == nil {
		return
	}
	path := baseline.Path(root, cfg)
	if _, err := os.Stat(path); err != nil {
		return
	}
	file, err := baseline.Load(path)
	if err != nil {
		return
	}
	rep.Findings = baseline.FilterFindings(rep.Findings, file)
	rep.Recompute()
}
