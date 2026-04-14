package rules

import "github.com/MauroProto/guard/internal/model"

type Spec struct {
	ID              string
	DefaultSeverity model.Severity
	Confidence      float64
	Description     string
	Rationale       string
	Evidence        string
	Remediation     string
}

var catalog = map[string]Spec{
	"repo.package_json.missing": {
		ID:              "repo.package_json.missing",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.99,
		Description:     "The repository root is missing package.json.",
		Rationale:       "Guard expects a pnpm/Node repository root to define package metadata and package manager behavior.",
		Evidence:        "Repository root lacks package.json.",
		Remediation:     "Create package.json or point Guard at the correct repo root.",
	},
	"repo.lockfile.missing": {
		ID:              "repo.lockfile.missing",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.99,
		Description:     "pnpm-lock.yaml is missing.",
		Rationale:       "Lockfiles are required for reproducible installs and dependency review.",
		Evidence:        "Repository root lacks pnpm-lock.yaml.",
		Remediation:     "Generate and commit pnpm-lock.yaml.",
	},
	"repo.packageManager.unpinned": {
		ID:              "repo.packageManager.unpinned",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.95,
		Description:     "packageManager is missing from package.json.",
		Rationale:       "Pinning the package manager version reduces drift across machines and CI.",
		Evidence:        "package.json has no packageManager field.",
		Remediation:     "Set packageManager to the pnpm version used by the repository.",
	},
	"repo.nodeEngine.missing": {
		ID:              "repo.nodeEngine.missing",
		DefaultSeverity: model.SeverityLow,
		Confidence:      0.9,
		Description:     "engines.node is missing from package.json.",
		Rationale:       "Declaring the supported Node version makes installs and CI behavior more predictable.",
		Evidence:        "package.json has no engines.node.",
		Remediation:     "Declare the minimum supported Node version.",
	},
	"pnpm.workspace.missing": {
		ID:              "pnpm.workspace.missing",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.98,
		Description:     "pnpm-workspace.yaml is missing.",
		Rationale:       "Guard relies on pnpm workspace defaults to reason about supply-chain posture.",
		Evidence:        "Repository root lacks pnpm-workspace.yaml.",
		Remediation:     "Create pnpm-workspace.yaml and define security defaults.",
	},
	"pnpm.minimumReleaseAge.missing": {
		ID:              "pnpm.minimumReleaseAge.missing",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.97,
		Description:     "minimumReleaseAge is not configured.",
		Rationale:       "Delaying new releases reduces exposure to compromised or rapidly yanked packages.",
		Evidence:        "pnpm-workspace.yaml has no minimumReleaseAge.",
		Remediation:     "Set minimumReleaseAge to the policy minimum.",
	},
	"pnpm.minimumReleaseAge.too_low": {
		ID:              "pnpm.minimumReleaseAge.too_low",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.94,
		Description:     "minimumReleaseAge is below policy.",
		Rationale:       "A shorter release delay weakens the repository's guardrails for fresh releases.",
		Evidence:        "Configured minimumReleaseAge is lower than the policy threshold.",
		Remediation:     "Raise minimumReleaseAge in pnpm-workspace.yaml.",
	},
	"pnpm.blockExoticSubdeps.disabled": {
		ID:              "pnpm.blockExoticSubdeps.disabled",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.98,
		Description:     "blockExoticSubdeps is disabled.",
		Rationale:       "Allowing exotic transitive sources increases exposure to unreviewed code sources.",
		Evidence:        "pnpm-workspace.yaml has blockExoticSubdeps disabled or unset.",
		Remediation:     "Enable blockExoticSubdeps in pnpm-workspace.yaml.",
	},
	"pnpm.strictDepBuilds.disabled": {
		ID:              "pnpm.strictDepBuilds.disabled",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.98,
		Description:     "strictDepBuilds is disabled.",
		Rationale:       "Dependency build approvals should be explicit to reduce install-time execution risk.",
		Evidence:        "pnpm-workspace.yaml has strictDepBuilds disabled or unset.",
		Remediation:     "Enable strictDepBuilds in pnpm-workspace.yaml.",
	},
	"pnpm.trustPolicy.disabled": {
		ID:              "pnpm.trustPolicy.disabled",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.92,
		Description:     "trustPolicy is not set to no-downgrade.",
		Rationale:       "Trust downgrade protection helps prevent registry trust regressions.",
		Evidence:        "pnpm-workspace.yaml does not use trustPolicy: no-downgrade.",
		Remediation:     "Set trustPolicy: no-downgrade.",
	},
	"pnpm.allowBuilds.unreviewed": {
		ID:              "pnpm.allowBuilds.unreviewed",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.95,
		Description:     "A package build approval is still pending.",
		Rationale:       "Install/build script execution should be explicitly approved and scoped.",
		Evidence:        "allowBuilds contains a package marked false.",
		Remediation:     "Review the package and approve or remove it.",
	},
	"github.workflow.permissions.missing": {
		ID:              "github.workflow.permissions.missing",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.96,
		Description:     "Workflow is missing top-level permissions.",
		Rationale:       "Explicit token permissions reduce accidental privilege escalation in GitHub Actions.",
		Evidence:        "Workflow YAML has no top-level permissions block.",
		Remediation:     "Add a top-level permissions block with minimum scopes.",
	},
	"github.workflow.token_permissions.broad": {
		ID:              "github.workflow.token_permissions.broad",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.94,
		Description:     "Workflow grants broad top-level write permissions.",
		Rationale:       "Broad default token permissions increase blast radius across all jobs.",
		Evidence:        "Top-level permissions block grants write scopes.",
		Remediation:     "Tighten the top-level permissions block to read-only defaults.",
	},
	"github.workflow.job_permissions.broad": {
		ID:              "github.workflow.job_permissions.broad",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.92,
		Description:     "A workflow job grants broad write permissions.",
		Rationale:       "Job-specific write scopes should be rare, explicit and limited to trusted jobs.",
		Evidence:        "Job permissions block grants write scopes.",
		Remediation:     "Reduce job-level permissions or isolate the privileged job.",
	},
	"github.workflow.unpinned_action": {
		ID:              "github.workflow.unpinned_action",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.97,
		Description:     "Workflow action or reusable workflow is not pinned to a full SHA.",
		Rationale:       "Mutable refs allow upstream changes to alter workflow behavior without a PR in this repo.",
		Evidence:        "uses: owner/repo@tag or @branch instead of a 40-character commit SHA.",
		Remediation:     "Pin the action or reusable workflow to a full commit SHA.",
	},
	"github.workflow.codeowners.missing": {
		ID:              "github.workflow.codeowners.missing",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.9,
		Description:     "Repository has workflows but no CODEOWNERS protection.",
		Rationale:       "Workflow changes are high-risk and should require review.",
		Evidence:        "Workflows exist but .github/CODEOWNERS is missing.",
		Remediation:     "Protect workflow changes with CODEOWNERS review.",
	},
	"github.workflow.pull_request_target.unsafe": {
		ID:              "github.workflow.pull_request_target.unsafe",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.88,
		Description:     "pull_request_target workflow checks out or executes PR code.",
		Rationale:       "pull_request_target runs with repository privileges and should not process untrusted PR code directly.",
		Evidence:        "Workflow uses pull_request_target and a step checks out or executes code.",
		Remediation:     "Avoid checking out PR code in pull_request_target or split privileged actions into a trusted workflow.",
	},
	"github.workflow.workflow_run.privileged": {
		ID:              "github.workflow.workflow_run.privileged",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.8,
		Description:     "workflow_run can trigger a privileged follow-up workflow.",
		Rationale:       "workflow_run can bridge trust boundaries between untrusted and trusted workflows.",
		Evidence:        "Workflow is triggered by workflow_run and contains elevated permissions or publish steps.",
		Remediation:     "Review the trust boundary and isolate privileged work from untrusted triggers.",
	},
	"github.workflow.publish.attestations.missing": {
		ID:              "github.workflow.publish.attestations.missing",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.84,
		Description:     "Publish workflow does not appear to generate attestations.",
		Rationale:       "Release provenance and attestations strengthen the supply-chain story of published artifacts.",
		Evidence:        "Publish step detected without an attestation step or attestation permission.",
		Remediation:     "Add artifact attestations to the publish/release workflow.",
	},
	"github.workflow.publish.permissions.broad": {
		ID:              "github.workflow.publish.permissions.broad",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.86,
		Description:     "Publish job grants broad write permissions.",
		Rationale:       "Publishing should happen in tightly scoped privileged jobs.",
		Evidence:        "Job contains publish steps and broad write permissions.",
		Remediation:     "Reduce publish job permissions to the minimum scopes required.",
	},
	"osv.vulnerability": {
		ID:              "osv.vulnerability",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.93,
		Description:     "Dependency is affected by an OSV advisory.",
		Rationale:       "Known vulnerabilities should be reviewed before shipping or upgrading.",
		Evidence:        "OSV returned one or more advisories for the package version.",
		Remediation:     "Upgrade to a patched version or document a temporary exception.",
	},
	"review.diff.install_script.added": {
		ID:              "review.diff.install_script.added",
		DefaultSeverity: model.SeverityCritical,
		Confidence:      0.98,
		Description:     "Upgrade adds a new install lifecycle script.",
		Rationale:       "Install scripts execute during dependency installation and are a high-value supply-chain risk signal.",
		Evidence:        "Tarball diff shows a new preinstall/install/postinstall/prepare script.",
		Remediation:     "Review the upgrade carefully and block it unless the new install script is justified.",
	},
	"review.diff.bin.added": {
		ID:              "review.diff.bin.added",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.9,
		Description:     "Upgrade adds a new binary artifact.",
		Rationale:       "New binaries increase the amount of opaque code shipped to consumers.",
		Evidence:        "Tarball diff contains a new binary file.",
		Remediation:     "Review the new binary and confirm it is expected for this upgrade.",
	},
	"review.diff.remote_url.added": {
		ID:              "review.diff.remote_url.added",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.94,
		Description:     "Upgrade adds remote fetch or command-execution patterns.",
		Rationale:       "New network fetches or command execution are strong indicators of elevated supply-chain risk.",
		Evidence:        "Tarball diff introduces curl/fetch/request or child_process patterns.",
		Remediation:     "Review the code change and verify the new behavior is intentional and safe.",
	},
	"review.trust.publisher.changed": {
		ID:              "review.trust.publisher.changed",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.8,
		Description:     "Package publisher changed between versions.",
		Rationale:       "A new publisher can indicate account transfer, compromise or a new publishing pipeline.",
		Evidence:        "Registry metadata shows different _npmUser values across versions.",
		Remediation:     "Verify that the publisher change is expected before merging the upgrade.",
	},
	"review.trust.provenance.lost": {
		ID:              "review.trust.provenance.lost",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.75,
		Description:     "Package lost provenance/trust metadata between versions.",
		Rationale:       "A drop in publication trust signals should trigger manual review even if the code diff looks small.",
		Evidence:        "Registry metadata exposed provenance/trusted-publishing indicators before but not after.",
		Remediation:     "Verify the release pipeline and metadata change before merging.",
	},
	"review.trust.semver.unexpected_change": {
		ID:              "review.trust.semver.unexpected_change",
		DefaultSeverity: model.SeverityMedium,
		Confidence:      0.78,
		Description:     "Upgrade behavior is unexpected for the declared semver delta.",
		Rationale:       "Patch/minor upgrades that add high-risk behavior deserve extra scrutiny.",
		Evidence:        "Semver delta is small but the tarball diff introduces risky signals.",
		Remediation:     "Treat the upgrade as suspicious and require manual review.",
	},
	"review.osv.new_advisory": {
		ID:              "review.osv.new_advisory",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.93,
		Description:     "Upgrade introduces new OSV advisories.",
		Rationale:       "A dependency review should fail loudly when the target version adds known vulnerabilities.",
		Evidence:        "OSV advisories are present for the target version and absent in the previous version.",
		Remediation:     "Pick a safer version or document an explicit exception.",
	},
	"policy.exception.expired": {
		ID:              "policy.exception.expired",
		DefaultSeverity: model.SeverityHigh,
		Confidence:      0.99,
		Description:     "A configured exception has expired.",
		Rationale:       "Expired exceptions should not silently keep muting findings.",
		Evidence:        "Exception expiration date is in the past.",
		Remediation:     "Remove the exception or renew it explicitly.",
	},
}

func Get(id string) (Spec, bool) {
	spec, ok := catalog[id]
	return spec, ok
}

func Known(id string) bool {
	_, ok := catalog[id]
	return ok
}

func All() map[string]Spec {
	out := make(map[string]Spec, len(catalog))
	for id, spec := range catalog {
		out[id] = spec
	}
	return out
}

func ApplyDefaults(f *model.Finding) {
	if f == nil {
		return
	}
	if spec, ok := Get(f.RuleID); ok {
		if f.Severity == "" {
			f.Severity = spec.DefaultSeverity
		}
		if f.Confidence == 0 {
			f.Confidence = spec.Confidence
		}
	}
	f.Normalize()
}
