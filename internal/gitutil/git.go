package gitutil

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ResolveDefaultBase(ctx context.Context, root, head string) (string, error) {
	candidates := []string{"origin/HEAD", "origin/main", "origin/master"}
	for _, ref := range candidates {
		if !refExists(ctx, root, ref) {
			continue
		}
		base, err := Output(ctx, root, "merge-base", head, ref)
		if err == nil && strings.TrimSpace(base) != "" {
			return strings.TrimSpace(base), nil
		}
	}
	return "", fmt.Errorf("could not resolve a base ref from origin/HEAD, origin/main, or origin/master")
}

func ChangedFiles(ctx context.Context, root, base, head string) ([]string, error) {
	out, err := Output(ctx, root, "diff", "--name-only", base, head)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out) == "" {
		return nil, nil
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	files := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		files = append(files, filepath.ToSlash(line))
	}
	return files, nil
}

func WorkingTreeChangedFiles(ctx context.Context, root string) ([]string, error) {
	seen := map[string]bool{}
	var files []string

	collect := func(args ...string) error {
		out, err := Output(ctx, root, args...)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			line = filepath.ToSlash(line)
			if seen[line] {
				continue
			}
			seen[line] = true
			files = append(files, line)
		}
		return nil
	}

	if refExists(ctx, root, "HEAD") {
		if err := collect("diff", "--name-only", "HEAD", "--"); err != nil {
			return nil, err
		}
	} else {
		if err := collect("diff", "--name-only", "--cached", "--"); err != nil {
			return nil, err
		}
		if err := collect("diff", "--name-only", "--"); err != nil {
			return nil, err
		}
	}
	if err := collect("ls-files", "--others", "--exclude-standard"); err != nil {
		return nil, err
	}
	return files, nil
}

func ShowFile(ctx context.Context, root, ref, relPath string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", root, "show", ref+":"+filepath.ToSlash(relPath))
	return cmd.Output()
}

func ExportTree(ctx context.Context, root, ref, dest string) error {
	archive := exec.CommandContext(ctx, "git", "-C", root, "archive", ref)
	reader, err := archive.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	archive.Stderr = &stderr

	extract := exec.CommandContext(ctx, "tar", "-x", "-C", dest)
	extract.Stdin = reader
	var extractStderr bytes.Buffer
	extract.Stderr = &extractStderr

	if err := archive.Start(); err != nil {
		return err
	}
	if err := extract.Start(); err != nil {
		_ = archive.Process.Kill()
		return err
	}
	archiveErr := archive.Wait()
	extractErr := extract.Wait()
	if archiveErr != nil {
		return fmt.Errorf("git archive %s: %v: %s", ref, archiveErr, strings.TrimSpace(stderr.String()))
	}
	if extractErr != nil {
		return fmt.Errorf("extract archive %s: %v: %s", ref, extractErr, strings.TrimSpace(extractStderr.String()))
	}
	return nil
}

func Output(ctx context.Context, root string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

func CurrentHead(ctx context.Context, root string) (string, error) {
	return Output(ctx, root, "rev-parse", "HEAD")
}

func refExists(ctx context.Context, root, ref string) bool {
	cmd := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--verify", ref)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

func WriteRefFile(ctx context.Context, root, ref, relPath, destRoot string) (string, error) {
	content, err := ShowFile(ctx, root, ref, relPath)
	if err != nil {
		return "", err
	}
	target := filepath.Join(destRoot, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(target, content, 0o644); err != nil {
		return "", err
	}
	return target, nil
}
