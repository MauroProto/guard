package review

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MauroProto/guard/internal/diff"
	"github.com/MauroProto/guard/internal/model"
	"github.com/MauroProto/guard/internal/npm"
	"github.com/MauroProto/guard/internal/osv"
)

func TestRunPRReviewDetectsInstallScriptUpgrade(t *testing.T) {
	root := t.TempDir()
	initGitRepo(t, root)

	writeFile(t, filepath.Join(root, ".guard", "policy.yaml"), `version: 1
github:
  requireCodeownersForWorkflows: false
pnpm:
  requireNodeEngine: false
osv:
  enabled: true
`)
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo-root","version":"1.0.0","packageManager":"pnpm@10.20.0"}`)
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages: []\nminimumReleaseAge: 1440\nblockExoticSubdeps: true\nstrictDepBuilds: true\ntrustPolicy: no-downgrade\n")
	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      demo:
        version: 1.0.0
packages:
  demo@1.0.0:
    resolution: {integrity: sha512-old}
`)
	commit(t, root, "base")
	base := revParse(t, root, "HEAD")

	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      demo:
        version: 1.0.1
packages:
  demo@1.0.1:
    resolution: {integrity: sha512-new}
`)
	commit(t, root, "head")
	head := revParse(t, root, "HEAD")

	result, err := RunPRReview(context.Background(), root, Options{
		Base: base,
		Head: head,
		Registry: fakeRegistry{
			versions: map[string]*npm.VersionMetadata{
				"demo@1.0.0": {Name: "demo", Version: "1.0.0", Publisher: "alice", RegistryHost: "registry.npmjs.org", Provenance: true},
				"demo@1.0.1": {Name: "demo", Version: "1.0.1", Publisher: "alice", RegistryHost: "registry.npmjs.org", Provenance: true},
			},
		},
		OSVClient: fakeOSV{},
		LoadPackage: func(ctx context.Context, root, name, version string) (*diff.PackageContents, error) {
			if version == "1.0.0" {
				return &diff.PackageContents{
					PackageJSON: map[string]any{"name": "demo", "version": "1.0.0", "scripts": map[string]any{}},
					Files:       map[string][]byte{"package.json": []byte(`{"name":"demo","version":"1.0.0"}`)},
					FileList:    []string{"package.json"},
				}, nil
			}
			return &diff.PackageContents{
				PackageJSON: map[string]any{"name": "demo", "version": "1.0.1", "scripts": map[string]any{"postinstall": "node install.js"}},
				Files:       map[string][]byte{"package.json": []byte(`{"name":"demo","version":"1.0.1","scripts":{"postinstall":"node install.js"}}`)},
				FileList:    []string{"package.json"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("review-pr failed: %v", err)
	}
	if result.Decision != "fail" {
		t.Fatalf("expected fail decision, got %+v", result)
	}
	if len(result.ChangedPackages) != 1 || result.ChangedPackages[0] != "demo" {
		t.Fatalf("expected changed package demo, got %+v", result.ChangedPackages)
	}
	if !hasReviewRule(result.Findings, "review.diff.install_script.added") {
		t.Fatalf("expected install-script finding, got %+v", result.Findings)
	}
}

func TestRunPRReviewDetectsUnsafeWorkflowChange(t *testing.T) {
	root := t.TempDir()
	initGitRepo(t, root)

	writeFile(t, filepath.Join(root, ".guard", "policy.yaml"), `version: 1
github:
  requireCodeownersForWorkflows: false
pnpm:
  requireNodeEngine: false
`)
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"demo-root","version":"1.0.0","packageManager":"pnpm@10.20.0"}`)
	writeFile(t, filepath.Join(root, "pnpm-workspace.yaml"), "packages: []\nminimumReleaseAge: 1440\nblockExoticSubdeps: true\nstrictDepBuilds: true\ntrustPolicy: no-downgrade\n")
	writeFile(t, filepath.Join(root, "pnpm-lock.yaml"), `lockfileVersion: '9.0'
importers:
  .: {}
packages: {}
`)
	writeFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), `name: CI
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
`)
	commit(t, root, "base")
	base := revParse(t, root, "HEAD")

	writeFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), `name: CI
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd
`)
	commit(t, root, "head")
	head := revParse(t, root, "HEAD")

	result, err := RunPRReview(context.Background(), root, Options{
		Base:       base,
		Head:       head,
		DisableOSV: true,
	})
	if err != nil {
		t.Fatalf("review-pr failed: %v", err)
	}
	if !hasReviewRule(result.Findings, "github.workflow.pull_request_target.unsafe") {
		t.Fatalf("expected pull_request_target finding, got %+v", result.Findings)
	}
	if len(result.WorkflowFindings) == 0 {
		t.Fatalf("expected workflow findings, got %+v", result)
	}
}

type fakeRegistry struct {
	versions map[string]*npm.VersionMetadata
}

func (f fakeRegistry) Version(_ context.Context, name, version string) (*npm.VersionMetadata, error) {
	if meta, ok := f.versions[name+"@"+version]; ok {
		return meta, nil
	}
	return &npm.VersionMetadata{Name: name, Version: version}, nil
}

type fakeOSV struct{}

func (fakeOSV) Query(_ context.Context, _ osv.Query) ([]osv.Advisory, error) {
	return nil, nil
}

func hasReviewRule(findings []model.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}

func initGitRepo(t *testing.T, root string) {
	t.Helper()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "guard@example.com")
	runGit(t, root, "config", "user.name", "Guard")
}

func commit(t *testing.T, root, message string) {
	t.Helper()
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", message)
}

func revParse(t *testing.T, root, ref string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", root, "rev-parse", ref)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse %s: %v", ref, err)
	}
	return strings.TrimSpace(string(out))
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2026-04-13T12:00:00Z",
		"GIT_COMMITTER_DATE=2026-04-13T12:00:00Z",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
