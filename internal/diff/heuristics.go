package diff

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"guard/internal/model"
)

// installScriptKeys are the package.json scripts that run during install.
var installScriptKeys = []string{"preinstall", "install", "postinstall", "prepare"}

// checkInstallScripts detects new or changed install lifecycle scripts.
func checkInstallScripts(from, to *PackageContents) []Signal {
	var signals []Signal
	fromScripts := extractScripts(from)
	toScripts := extractScripts(to)

	for _, key := range installScriptKeys {
		oldVal, hadOld := fromScripts[key]
		newVal, hasNew := toScripts[key]
		if hasNew && !hadOld {
			signals = append(signals, Signal{
				ID:       "diff.install_script.added",
				Severity: model.SeverityCritical,
				Title:    "Install script added",
				Message:  key + " script was added: " + truncate(newVal, 120),
				Evidence: map[string]any{"script": key, "value": newVal},
			})
		} else if hasNew && hadOld && oldVal != newVal {
			signals = append(signals, Signal{
				ID:       "diff.install_script.changed",
				Severity: model.SeverityHigh,
				Title:    "Install script changed",
				Message:  key + " script was modified.",
				Evidence: map[string]any{"script": key, "old": truncate(oldVal, 80), "new": truncate(newVal, 80)},
			})
		}
	}
	return signals
}

// remotePatterns detects network access and command execution.
var remotePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bcurl\b`),
	regexp.MustCompile(`\bwget\b`),
	regexp.MustCompile(`\bfetch\s*\(`),
	regexp.MustCompile(`\bhttps?\.request\b`),
	regexp.MustCompile(`\bchild_process\.(exec|spawn|execFile)\b`),
}

// checkRemoteURLs detects new remote fetch or command execution patterns in JS files.
func checkRemoteURLs(from, to *PackageContents) []Signal {
	var signals []Signal
	for path, content := range to.Files {
		if !isJSFile(path) {
			continue
		}
		oldContent := from.Files[path]
		newStr := string(content)
		oldStr := string(oldContent)

		for _, pat := range remotePatterns {
			if pat.MatchString(newStr) && !pat.MatchString(oldStr) {
				signals = append(signals, Signal{
					ID:       "diff.remote_url.added",
					Severity: model.SeverityHigh,
					Title:    "Remote fetch or command execution detected",
					Message:  "New pattern found: " + pat.String(),
					File:     path,
					Evidence: map[string]any{"pattern": pat.String()},
				})
			}
		}
	}
	return signals
}

// binaryExtensions are file extensions that indicate binary files.
var binaryExtensions = map[string]bool{
	".node": true, ".so": true, ".dll": true, ".dylib": true,
	".exe": true, ".wasm": true, ".bin": true,
}

// checkBinaries detects new binary files.
func checkBinaries(from, to *PackageContents) []Signal {
	var signals []Signal
	for path, content := range to.Files {
		if _, existed := from.Files[path]; existed {
			continue
		}
		ext := filepath.Ext(path)
		isBinary := binaryExtensions[ext] || !utf8.Valid(content)
		if isBinary {
			signals = append(signals, Signal{
				ID:       "diff.binary.added",
				Severity: model.SeverityMedium,
				Title:    "New binary file detected",
				Message:  "Binary file added: " + path,
				File:     path,
			})
		}
	}
	return signals
}

// obfuscation patterns
var (
	longHexPattern    = regexp.MustCompile(`[0-9a-fA-F]{256,}`)
	longBase64Pattern = regexp.MustCompile(`[A-Za-z0-9+/=]{256,}`)
	evalPattern       = regexp.MustCompile(`\beval\s*\(`)
	newFuncPattern    = regexp.MustCompile(`\bnew\s+Function\s*\(`)
	vmPattern         = regexp.MustCompile(`\bvm\.Script\b`)
)

// checkObfuscation detects obfuscation signals like eval, long encoded strings, etc.
func checkObfuscation(from, to *PackageContents) []Signal {
	var signals []Signal
	for path, content := range to.Files {
		if !isJSFile(path) {
			continue
		}
		oldContent := from.Files[path]
		newStr := string(content)
		oldStr := string(oldContent)

		checks := []struct {
			pat  *regexp.Regexp
			desc string
		}{
			{evalPattern, "eval() call"},
			{newFuncPattern, "new Function() constructor"},
			{vmPattern, "vm.Script usage"},
			{longHexPattern, "long hex string (possible obfuscation)"},
			{longBase64Pattern, "long base64 string (possible obfuscation)"},
		}

		for _, c := range checks {
			if c.pat.MatchString(newStr) && !c.pat.MatchString(oldStr) {
				signals = append(signals, Signal{
					ID:       "diff.obfuscation.suspected",
					Severity: model.SeverityMedium,
					Title:    "Suspected obfuscation",
					Message:  c.desc + " in " + path,
					File:     path,
					Evidence: map[string]any{"pattern": c.desc},
				})
			}
		}
	}
	return signals
}

// sensitivePathPatterns detect access to sensitive locations.
var sensitivePathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.env\b`),
	regexp.MustCompile(`\.npmrc\b`),
	regexp.MustCompile(`\.ssh[/\\]`),
	regexp.MustCompile(`\.aws[/\\]`),
	regexp.MustCompile(`wallet`),
	regexp.MustCompile(`chrome[/\\]`),
	regexp.MustCompile(`firefox[/\\]`),
}

// checkSensitivePaths detects new access to sensitive filesystem paths.
func checkSensitivePaths(from, to *PackageContents) []Signal {
	var signals []Signal
	for path, content := range to.Files {
		if !isJSFile(path) {
			continue
		}
		oldContent := from.Files[path]
		newStr := string(content)
		oldStr := string(oldContent)

		for _, pat := range sensitivePathPatterns {
			if pat.MatchString(newStr) && !pat.MatchString(oldStr) {
				signals = append(signals, Signal{
					ID:       "diff.sensitive_path_access.added",
					Severity: model.SeverityHigh,
					Title:    "Sensitive path access detected",
					Message:  "New reference to sensitive path: " + pat.String(),
					File:     path,
					Evidence: map[string]any{"pattern": pat.String()},
				})
			}
		}
	}
	return signals
}

// checkSuspiciousAPIs checks for new usage of configurable suspicious APIs.
func checkSuspiciousAPIs(apis []string) Heuristic {
	patterns := make([]*regexp.Regexp, 0, len(apis))
	for _, api := range apis {
		escaped := regexp.QuoteMeta(api)
		patterns = append(patterns, regexp.MustCompile(`\b`+escaped+`\b`))
	}
	return func(from, to *PackageContents) []Signal {
		var signals []Signal
		for path, content := range to.Files {
			if !isJSFile(path) {
				continue
			}
			oldContent := from.Files[path]
			newStr := string(content)
			oldStr := string(oldContent)

			for i, pat := range patterns {
				if pat.MatchString(newStr) && !pat.MatchString(oldStr) {
					signals = append(signals, Signal{
						ID:       "diff.suspicious_api.added",
						Severity: model.SeverityMedium,
						Title:    "Suspicious API usage detected",
						Message:  "New usage of " + apis[i],
						File:     path,
						Evidence: map[string]any{"api": apis[i]},
					})
				}
			}
		}
		return signals
	}
}

func extractScripts(pc *PackageContents) map[string]string {
	if pc == nil || pc.PackageJSON == nil {
		return nil
	}
	scriptsRaw, ok := pc.PackageJSON["scripts"]
	if !ok {
		return nil
	}
	b, err := json.Marshal(scriptsRaw)
	if err != nil {
		return nil
	}
	var scripts map[string]string
	if err := json.Unmarshal(b, &scripts); err != nil {
		return nil
	}
	return scripts
}

func isJSFile(path string) bool {
	ext := filepath.Ext(path)
	switch ext {
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx":
		return true
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// shellExtensions detect new shell scripts.
var shellExtensions = map[string]bool{
	".sh": true, ".bash": true, ".ps1": true, ".bat": true, ".cmd": true,
}

// checkStructuralChanges detects disproportionate file count changes and new shell scripts.
func checkStructuralChanges(from, to *PackageContents) []Signal {
	var signals []Signal

	fromCount := len(from.FileList)
	toCount := len(to.FileList)
	if fromCount > 0 && toCount > fromCount*3 {
		signals = append(signals, Signal{
			ID:       "diff.structural.file_count_spike",
			Severity: model.SeverityLow,
			Title:    "Significant increase in file count",
			Message:  strings.Join([]string{"File count went from", fmt.Sprint(fromCount), "to", fmt.Sprint(toCount)}, " "),
			Evidence: map[string]any{"from_count": fromCount, "to_count": toCount},
		})
	}

	for path := range to.Files {
		if _, existed := from.Files[path]; existed {
			continue
		}
		ext := filepath.Ext(path)
		if shellExtensions[ext] {
			signals = append(signals, Signal{
				ID:       "diff.structural.shell_script_added",
				Severity: model.SeverityMedium,
				Title:    "New shell script added",
				Message:  "Shell script added: " + path,
				File:     path,
			})
		}
	}

	return signals
}

