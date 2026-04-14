package engine

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/MauroProto/guard/internal/config"
)

type ScanScope string

const (
	ScanScopeAll       ScanScope = "all"
	ScanScopeRepo      ScanScope = "repo"
	ScanScopeWorkspace ScanScope = "workspace"
	ScanScopeDeps      ScanScope = "deps"
	ScanScopeWorkflows ScanScope = "workflows"
	ScanScopePolicy    ScanScope = "policy"
)

type ScanTargets struct {
	RepoStructure      bool
	PackageMetadata    bool
	WorkspacePosture   bool
	BuildApprovals     bool
	OSV                bool
	WorkflowAudit      bool
	WorkflowCodeowners bool
	PolicyLint         bool
	PackageFiles       map[string]bool
	WorkflowFiles      map[string]bool
}

func ParseScanScope(value string) (ScanScope, error) {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "", string(ScanScopeAll):
		return ScanScopeAll, nil
	case string(ScanScopeRepo):
		return ScanScopeRepo, nil
	case string(ScanScopeWorkspace):
		return ScanScopeWorkspace, nil
	case string(ScanScopeDeps):
		return ScanScopeDeps, nil
	case string(ScanScopeWorkflows):
		return ScanScopeWorkflows, nil
	case string(ScanScopePolicy):
		return ScanScopePolicy, nil
	default:
		return "", fmt.Errorf("unknown scan scope: %s", value)
	}
}

func ResolveScanTargets(cfg *config.Config, opts *ScanOptions) (ScanTargets, error) {
	scope, err := ParseScanScope("")
	if opts != nil {
		scope, err = ParseScanScope(opts.Scope)
	}
	if err != nil {
		return ScanTargets{}, err
	}

	targets := defaultTargetsForScope(scope)
	if !hasFileFilter(opts) {
		return targets, nil
	}

	affected := classifyFiles(cfg, opts.Files)
	targets.RepoStructure = targets.RepoStructure && affected.RepoStructure
	targets.PackageMetadata = targets.PackageMetadata && affected.PackageMetadata
	targets.WorkspacePosture = targets.WorkspacePosture && affected.WorkspacePosture
	targets.BuildApprovals = targets.BuildApprovals && affected.BuildApprovals
	targets.OSV = targets.OSV && affected.OSV
	targets.WorkflowAudit = targets.WorkflowAudit && affected.WorkflowAudit
	targets.WorkflowCodeowners = targets.WorkflowCodeowners && affected.WorkflowCodeowners
	if scope == ScanScopeAll {
		targets.PolicyLint = affected.PolicyLint
	} else {
		targets.PolicyLint = targets.PolicyLint && affected.PolicyLint
	}
	targets.PackageFiles = affected.PackageFiles
	targets.WorkflowFiles = affected.WorkflowFiles
	return targets, nil
}

func (t ScanTargets) Any() bool {
	return t.RepoStructure ||
		t.PackageMetadata ||
		t.WorkspacePosture ||
		t.BuildApprovals ||
		t.OSV ||
		t.WorkflowAudit ||
		t.WorkflowCodeowners ||
		t.PolicyLint
}

func (t ScanTargets) NeedsRepoState() bool {
	return t.RepoStructure ||
		t.PackageMetadata ||
		t.WorkspacePosture ||
		t.BuildApprovals ||
		t.WorkflowAudit ||
		t.WorkflowCodeowners
}

func (t ScanTargets) IncludesPackageFile(rel string) bool {
	if !t.PackageMetadata {
		return false
	}
	if t.PackageFiles == nil {
		return true
	}
	return t.PackageFiles[filepath.ToSlash(rel)]
}

func (t ScanTargets) IncludesWorkflowFile(rel string) bool {
	if !t.WorkflowAudit {
		return false
	}
	if t.WorkflowFiles == nil {
		return true
	}
	return t.WorkflowFiles[filepath.ToSlash(rel)]
}

func defaultTargetsForScope(scope ScanScope) ScanTargets {
	switch scope {
	case ScanScopeRepo:
		return ScanTargets{
			RepoStructure:   true,
			PackageMetadata: true,
		}
	case ScanScopeWorkspace:
		return ScanTargets{
			WorkspacePosture: true,
			BuildApprovals:   true,
		}
	case ScanScopeDeps:
		return ScanTargets{
			RepoStructure:   true,
			PackageMetadata: true,
			BuildApprovals:  true,
			OSV:             true,
		}
	case ScanScopeWorkflows:
		return ScanTargets{
			WorkflowAudit:      true,
			WorkflowCodeowners: true,
		}
	case ScanScopePolicy:
		return ScanTargets{
			PolicyLint: true,
		}
	default:
		return ScanTargets{
			RepoStructure:      true,
			PackageMetadata:    true,
			WorkspacePosture:   true,
			BuildApprovals:     true,
			OSV:                true,
			WorkflowAudit:      true,
			WorkflowCodeowners: true,
		}
	}
}

type affectedFiles struct {
	RepoStructure      bool
	PackageMetadata    bool
	WorkspacePosture   bool
	BuildApprovals     bool
	OSV                bool
	WorkflowAudit      bool
	WorkflowCodeowners bool
	PolicyLint         bool
	PackageFiles       map[string]bool
	WorkflowFiles      map[string]bool
}

func classifyFiles(cfg *config.Config, files []string) affectedFiles {
	affected := affectedFiles{
		PackageFiles:  map[string]bool{},
		WorkflowFiles: map[string]bool{},
	}
	for _, rel := range files {
		rel = normalizeRelPath(rel)
		if rel == "" {
			continue
		}
		switch {
		case rel == "pnpm-workspace.yaml":
			affected.WorkspacePosture = true
			affected.BuildApprovals = true
		case rel == "pnpm-lock.yaml":
			affected.RepoStructure = true
			affected.BuildApprovals = true
			affected.OSV = true
		case rel == filepath.ToSlash(config.DefaultPolicyPath):
			affected.PolicyLint = true
		case isCodeownersFile(rel):
			affected.WorkflowCodeowners = true
		case path.Base(rel) == "package.json":
			affected.RepoStructure = true
			affected.PackageMetadata = true
			affected.PackageFiles[rel] = true
		case isWorkflowFile(cfg, rel):
			affected.WorkflowAudit = true
			affected.WorkflowCodeowners = true
			affected.WorkflowFiles[rel] = true
		}
	}
	if len(affected.PackageFiles) == 0 {
		affected.PackageFiles = nil
	}
	if len(affected.WorkflowFiles) == 0 {
		affected.WorkflowFiles = nil
	}
	return affected
}

func hasFileFilter(opts *ScanOptions) bool {
	return opts != nil && (opts.ChangedFiles || len(opts.Files) > 0)
}

func normalizeRelPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(value))
}

func isCodeownersFile(rel string) bool {
	switch normalizeRelPath(rel) {
	case "CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS":
		return true
	default:
		return false
	}
}

func isWorkflowFile(cfg *config.Config, rel string) bool {
	rel = normalizeRelPath(rel)
	ext := strings.ToLower(path.Ext(rel))
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	paths := []string{".github/workflows"}
	if cfg != nil && len(cfg.GitHub.WorkflowPaths) > 0 {
		paths = cfg.GitHub.WorkflowPaths
	}
	for _, base := range paths {
		base = normalizeRelPath(base)
		if rel == base || strings.HasPrefix(rel, strings.TrimSuffix(base, "/")+"/") {
			return true
		}
	}
	return false
}
