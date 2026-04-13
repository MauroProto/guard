package diff

import "github.com/MauroProto/guard/internal/model"

// Compare runs all heuristics against two package versions and returns a DiffResult.
func Compare(target Target, from, to *PackageContents, suspiciousAPIs []string) *DiffResult {
	heuristics := []Heuristic{
		checkInstallScripts,
		checkRemoteURLs,
		checkBinaries,
		checkObfuscation,
		checkSensitivePaths,
		checkSuspiciousAPIs(suspiciousAPIs),
		checkStructuralChanges,
	}

	var signals []Signal
	for _, h := range heuristics {
		signals = append(signals, h(from, to)...)
	}
	if signals == nil {
		signals = []Signal{}
	}

	return &DiffResult{
		Target:  target,
		Signals: signals,
		Score:   scoreDiff(signals),
		Summary: summarizeDiff(signals),
	}
}

func scoreDiff(signals []Signal) int {
	total := 0
	for _, s := range signals {
		switch s.Severity {
		case model.SeverityCritical:
			total += 40
		case model.SeverityHigh:
			total += 20
		case model.SeverityMedium:
			total += 8
		default:
			total += 3
		}
	}
	if total > 100 {
		return 100
	}
	return total
}

func summarizeDiff(signals []Signal) string {
	if len(signals) == 0 {
		return "No risk signals detected."
	}
	critical := 0
	high := 0
	for _, s := range signals {
		switch s.Severity {
		case model.SeverityCritical:
			critical++
		case model.SeverityHigh:
			high++
		}
	}
	if critical > 0 {
		return "Critical risk signals detected. Manual review strongly recommended."
	}
	if high > 0 {
		return "High risk signals detected. Review before updating."
	}
	return "Moderate risk signals detected. Review recommended."
}
