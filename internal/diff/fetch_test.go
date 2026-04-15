package diff

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyIntegritySHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg.tgz")
	payload := []byte("fixture-content")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	sum := sha256.Sum256(payload)
	integrity := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	if err := verifyIntegrity(path, integrity); err != nil {
		t.Fatalf("expected integrity to pass: %v", err)
	}
}

func TestVerifyIntegritySHA512(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg.tgz")
	payload := []byte("fixture-content-sha512")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	sum := sha512.Sum512(payload)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	if err := verifyIntegrity(path, integrity); err != nil {
		t.Fatalf("expected integrity to pass: %v", err)
	}
}

func TestVerifyIntegrityMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg.tgz")
	payload := []byte("fixture-content")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	wrongSum := sha256.Sum256([]byte("different-content"))
	integrity := "sha256-" + base64.StdEncoding.EncodeToString(wrongSum[:])
	if err := verifyIntegrity(path, integrity); err == nil {
		t.Fatal("expected integrity mismatch error")
	}
}

func TestVerifyIntegrityInvalidFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkg.tgz")
	if err := os.WriteFile(path, []byte("fixture"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	if err := verifyIntegrity(path, "sha256"); err == nil {
		t.Fatal("expected unsupported integrity format error")
	}
}
