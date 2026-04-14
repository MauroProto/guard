package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MauroProto/guard/internal/config"
	"github.com/MauroProto/guard/internal/engine"
	"github.com/MauroProto/guard/internal/lockfile"
	"github.com/MauroProto/guard/internal/pnpm"
	"github.com/MauroProto/guard/internal/policy"
	"github.com/MauroProto/guard/internal/ui"
)

func runApproveBuild(args []string) error {
	// Extract positional package name.
	var pkg string
	var flagArgs []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && pkg == "" {
			pkg = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}
	if pkg == "" {
		return usageError("approve requires: guard approve <package-name>")
	}

	fs := flag.NewFlagSet("approve-build", flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	dryRun := fs.Bool("dry-run", false, "preview changes without writing")
	reason := fs.String("reason", "Approved via guard approve-build", "reason for the approval")
	version := fs.String("version", "", "package version to approve")
	importer := fs.String("importer", "", "workspace importer path")
	approvedBy := fs.String("approved-by", "", "actor approving the exception")
	noColor := fs.Bool("no-color", false, "disable colored output")
	if err := fs.Parse(flagArgs); err != nil {
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}

	if *noColor {
		ui.SetNoColor(true)
	}

	ui.Header(engine.Version)

	if *dryRun {
		ui.Info(fmt.Sprintf("Dry run — approving %s", pkg))
		ui.Newline()
		ui.FileWouldCreate(fmt.Sprintf("pnpm-workspace.yaml → allowBuilds[%q] = true", pkg))
		ui.FileWouldCreate(fmt.Sprintf(".guard/policy.yaml → package exception for %q", pkg))
		ui.Divider()
		ui.Newline()
		ui.Info(ui.T("init.done_dryrun"))
		ui.Newline()
		return nil
	}

	// Step 1: Load workspace
	sp := ui.NewSpinner("Loading workspace...")
	ws, err := pnpm.Load(*root)
	ui.Pause(300 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("load workspace: %v", err))
		return fmt.Errorf("load workspace: %w", err)
	}
	if ws.AllowBuilds == nil {
		ws.AllowBuilds = map[string]bool{}
	}
	sp.Stop()

	scope, err := resolveBuildApprovalScope(*root, pkg, *version, *importer)
	if err != nil {
		return err
	}

	// Step 2: Load policy
	sp = ui.NewSpinner("Loading policy...")
	cfg, err := config.Load(*root, "")
	ui.Pause(200 * time.Millisecond)
	if err != nil {
		sp.StopFail(fmt.Sprintf("%v", err))
		return err
	}
	sp.Stop()

	// Step 3: Update workspace
	sp = ui.NewSpinner(fmt.Sprintf("Updating pnpm-workspace.yaml → allowBuilds[%q]", pkg))
	ws.AllowBuilds[pkg] = true
	if err := pnpm.Save(*root, ws); err != nil {
		sp.StopFail(err.Error())
		return fmt.Errorf("save workspace: %w", err)
	}
	ui.Pause(300 * time.Millisecond)
	sp.Stop()

	// Step 4: Update policy
	now := time.Now().UTC()
	expiry := now.AddDate(0, 6, 0)
	sp = ui.NewSpinner(fmt.Sprintf("Updating .guard/policy.yaml → exception expires %s", expiry.Format(time.RFC3339)))
	policy.AddPackageException(cfg, policy.PackageApproval{
		Package:    pkg,
		Kind:       "build_script",
		Version:    scope.Version,
		Importer:   scope.Importer,
		RuleID:     "pnpm.allowBuilds.unreviewed",
		Reason:     *reason,
		ApprovedBy: *approvedBy,
		ApprovedAt: now,
		ExpiresAt:  expiry,
	})
	if err := config.Save(*root, "", cfg); err != nil {
		sp.StopFail(err.Error())
		return fmt.Errorf("save policy: %w", err)
	}
	ui.Pause(300 * time.Millisecond)
	sp.Stop()

	// Result
	ui.Divider()
	ui.Newline()
	ui.Success(fmt.Sprintf(ui.T("approve.done"), pkg))
	ui.Newline()
	return nil
}

type buildApprovalScope struct {
	Version  string
	Importer string
}

func resolveBuildApprovalScope(root, pkg, requestedVersion, requestedImporter string) (buildApprovalScope, error) {
	scope := buildApprovalScope{
		Version:  requestedVersion,
		Importer: requestedImporter,
	}
	lock, err := lockfile.Load(filepath.Join(root, "pnpm-lock.yaml"))
	if err != nil {
		return scope, nil
	}

	refs := lockfile.ResolvePackageRefs(lock, pkg)
	if requestedImporter != "" {
		filtered := refs[:0]
		for _, ref := range refs {
			if ref.Importer == requestedImporter {
				filtered = append(filtered, ref)
			}
		}
		if len(filtered) == 0 {
			return scope, usageError(fmt.Sprintf("approve-build: importer %s does not reference %s", requestedImporter, pkg))
		}
		refs = filtered
	}
	if requestedVersion != "" {
		filtered := refs[:0]
		for _, ref := range refs {
			if ref.Version == requestedVersion {
				filtered = append(filtered, ref)
			}
		}
		if len(filtered) == 0 && len(lockfile.ResolvePackageRefs(lock, pkg)) > 0 {
			return scope, usageError(fmt.Sprintf("approve-build: version %s not found for %s", requestedVersion, pkg))
		}
		refs = filtered
	}

	if requestedImporter == "" {
		importers := uniqueImporters(refs)
		if len(importers) > 1 {
			return scope, usageError(fmt.Sprintf("approve-build: %s appears in multiple importers: %s (use --importer)", pkg, strings.Join(importers, ", ")))
		}
	}
	if requestedVersion == "" {
		versions := uniqueVersions(refs)
		if len(versions) > 1 {
			return scope, usageError(fmt.Sprintf("approve-build: %s resolves to multiple versions: %s (use --version)", pkg, strings.Join(versions, ", ")))
		}
	}

	if len(refs) == 1 {
		if scope.Importer == "" {
			scope.Importer = refs[0].Importer
		}
		if scope.Version == "" {
			scope.Version = refs[0].Version
		}
	}

	return scope, nil
}

func uniqueImporters(refs []lockfile.PackageRef) []string {
	seen := map[string]bool{}
	var values []string
	for _, ref := range refs {
		if ref.Importer == "" || seen[ref.Importer] {
			continue
		}
		seen[ref.Importer] = true
		values = append(values, ref.Importer)
	}
	sort.Strings(values)
	return values
}

func uniqueVersions(refs []lockfile.PackageRef) []string {
	seen := map[string]bool{}
	var values []string
	for _, ref := range refs {
		if ref.Version == "" || seen[ref.Version] {
			continue
		}
		seen[ref.Version] = true
		values = append(values, ref.Version)
	}
	sort.Strings(values)
	return values
}
