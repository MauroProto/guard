package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunDiffReturnsPassWhenDisabledByPolicy(t *testing.T) {
	root := t.TempDir()
	beforeDir := filepath.Join("..", "..", "testdata", "diff", "before")
	afterDir := filepath.Join("..", "..", "testdata", "diff", "after")
	policy := `version: 1
diff:
  enabled: false
`
	if err := os.MkdirAll(filepath.Join(root, ".guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".guard", "policy.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout := captureStdout(t, func() {
		if err := runDiff([]string{"test@1.0.0..2.0.0", "--root", root, "--from-dir", beforeDir, "--to-dir", afterDir, "--format", "json", "--no-color"}); err != nil {
			t.Fatalf("expected disabled diff to return nil, got %v", err)
		}
	})
	if !strings.Contains(stdout, "disabled by policy") {
		t.Fatalf("expected disabled-by-policy output, got %q", stdout)
	}
}

func TestRunDiffFailsWhenConfiguredSignalIsPresent(t *testing.T) {
	root := t.TempDir()
	beforeDir := filepath.Join("..", "..", "testdata", "diff", "before")
	afterDir := filepath.Join("..", "..", "testdata", "diff", "after")
	policy := `version: 1
diff:
  enabled: true
  failOnSignals:
    - diff.install_script.added
`
	if err := os.MkdirAll(filepath.Join(root, ".guard"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".guard", "policy.yaml"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	err := runDiff([]string{"test@1.0.0..2.0.0", "--root", root, "--from-dir", beforeDir, "--to-dir", afterDir, "--format", "json", "--no-color"})
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("expected ErrPolicy, got %v", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() {
		os.Stdout = old
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
