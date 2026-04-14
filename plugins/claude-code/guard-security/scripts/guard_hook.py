#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCOPES = ("deps", "workspace", "policy", "workflows")
DEFAULT_WORKFLOW_DIRS = [".github/workflows"]
DEFAULT_MODE = "balanced"


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_event() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid hook JSON: {exc}") from exc
    if isinstance(data, dict):
        return data
    raise SystemExit("hook input must be a JSON object")


def emit(payload: dict[str, Any] | None) -> int:
    if payload:
        json.dump(payload, sys.stdout, separators=(",", ":"), sort_keys=True)
        sys.stdout.write("\n")
    return 0


def normalize_mode(value: str | None) -> str:
    mode = (value or DEFAULT_MODE).strip().lower()
    if mode not in {"observe", "balanced", "strict"}:
        return DEFAULT_MODE
    return mode


def repo_key(repo_root: Path) -> str:
    return hashlib.sha256(str(repo_root).encode("utf-8")).hexdigest()[:16]


def unique_sorted(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if not value:
            continue
        norm = os.path.normpath(value)
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    out.sort()
    return out


def find_repo_root(candidate: str | None) -> Path | None:
    if not candidate:
        return None
    path = Path(candidate).expanduser().resolve()
    if not path.exists():
        return None
    if path.is_file():
        path = path.parent

    git_root = git_toplevel(path)
    if git_root is not None:
        return git_root

    current = path
    while True:
        if (
            (current / ".git").exists()
            or (current / "pnpm-workspace.yaml").exists()
            or (current / ".guard" / "policy.yaml").exists()
            or (current / "package.json").exists()
        ):
            return current
        if current.parent == current:
            return None
        current = current.parent


def git_toplevel(path: Path) -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path),
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    if not value:
        return None
    root = Path(value).expanduser().resolve()
    return root if root.exists() else None


def default_scope_state() -> dict[str, Any]:
    return {
        "status": "clean",
        "pending": False,
        "blocking_count": 0,
        "warning_count": 0,
        "last_trigger": "",
        "last_run_at": "",
        "report_path": "",
        "last_files": [],
        "last_error": "",
        "needs_attention": False,
    }


def fresh_state(repo_root: Path, mode: str) -> dict[str, Any]:
    return {
        "repo_root": str(repo_root),
        "mode": mode,
        "session_id": "",
        "watch_paths": [],
        "scopes": {scope: default_scope_state() for scope in SCOPES},
    }


@dataclass
class Runtime:
    event: dict[str, Any]
    command_name: str

    def __post_init__(self) -> None:
        self.plugin_root = Path(
            os.environ.get("CLAUDE_PLUGIN_ROOT")
            or Path(__file__).resolve().parents[1]
        ).resolve()
        self.data_root = Path(
            os.environ.get("CLAUDE_PLUGIN_DATA") or self.plugin_root / ".plugin-data"
        ).resolve()
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.mode = normalize_mode(os.environ.get("GUARD_PLUGIN_MODE"))
        self.wrapper = self.plugin_root / "bin" / "guard-plugin"
        self.repo_root = self._resolve_repo_root()
        self.state = self._load_state()

    def _resolve_repo_root(self) -> Path | None:
        candidates = [
            os.environ.get("GUARD_REPO_ROOT"),
            self.event.get("new_cwd"),
            self.event.get("cwd"),
            os.environ.get("CLAUDE_WORKSPACE_ROOT"),
            os.environ.get("CLAUDE_PROJECT_DIR"),
            os.getcwd(),
        ]
        for candidate in candidates:
            root = find_repo_root(candidate)
            if root is not None:
                return root
        return None

    def repo_dir(self) -> Path | None:
        if self.repo_root is None:
            return None
        directory = self.data_root / "repos" / repo_key(self.repo_root)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "reports").mkdir(parents=True, exist_ok=True)
        return directory

    def state_path(self) -> Path | None:
        directory = self.repo_dir()
        return None if directory is None else directory / "state.json"

    def report_path(self, name: str) -> Path | None:
        directory = self.repo_dir()
        return None if directory is None else directory / "reports" / f"{name}.json"

    def _load_state(self) -> dict[str, Any] | None:
        if self.repo_root is None:
            return None
        path = self.state_path()
        assert path is not None
        if not path.exists():
            return fresh_state(self.repo_root, self.mode)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return fresh_state(self.repo_root, self.mode)
        if not isinstance(data, dict) or data.get("repo_root") != str(self.repo_root):
            return fresh_state(self.repo_root, self.mode)
        data.setdefault("scopes", {})
        for scope in SCOPES:
            scope_state = data["scopes"].setdefault(scope, {})
            defaults = default_scope_state()
            for key, value in defaults.items():
                scope_state.setdefault(key, value)
        data["mode"] = self.mode
        data.setdefault("watch_paths", [])
        return data

    def save_state(self) -> None:
        if self.state is None:
            return
        path = self.state_path()
        assert path is not None
        path.write_text(json.dumps(self.state, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def scope_state(self, scope: str) -> dict[str, Any]:
        assert self.state is not None
        return self.state["scopes"][scope]

    def clear_session_flags(self) -> None:
        if self.state is None:
            return
        for scope in SCOPES:
            state = self.scope_state(scope)
            state["pending"] = False
            state["needs_attention"] = False
            if state["last_trigger"] in {"pre_bash", "file_changed"}:
                state["last_trigger"] = ""

    def guard_available(self) -> tuple[bool, str]:
        if not self.wrapper.is_file():
            return False, f"wrapper missing at {self.wrapper}"
        proc = subprocess.run(
            [str(self.wrapper), "version"],
            cwd=str(self.repo_root) if self.repo_root else None,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            reason = proc.stderr.strip() or proc.stdout.strip() or "Guard CLI unavailable"
            return False, reason
        return True, proc.stdout.strip()

    def run_guard(
        self,
        args: list[str],
        *,
        report_name: str,
        allow_failure: bool = True,
    ) -> tuple[int, dict[str, Any] | None, str]:
        report_path = self.report_path(report_name)
        cmd = [str(self.wrapper), *args]
        proc = subprocess.run(
            cmd,
            cwd=str(self.repo_root) if self.repo_root else None,
            capture_output=True,
            text=True,
            check=False,
        )
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        data: dict[str, Any] | None = None
        if stdout:
            try:
                parsed = json.loads(stdout)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                data = parsed
        if report_path is not None and stdout:
            report_path.write_text(stdout + "\n", encoding="utf-8")
        if proc.returncode != 0 and not allow_failure and data is None:
            raise RuntimeError(stderr or stdout or f"guard command failed: {' '.join(args)}")
        return proc.returncode, data, stderr or stdout

    def workflow_dirs(self) -> list[str]:
        if self.repo_root is None:
            return []
        policy_path = self.repo_root / ".guard" / "policy.yaml"
        configured = parse_policy_workflow_paths(policy_path)
        if not configured:
            configured = DEFAULT_WORKFLOW_DIRS
        return configured

    def compute_watch_paths(self) -> list[str]:
        if self.repo_root is None:
            return []
        root = self.repo_root
        values: list[str] = [
            str(root / "package.json"),
            str(root / "pnpm-lock.yaml"),
            str(root / "pnpm-workspace.yaml"),
            str(root / ".guard" / "policy.yaml"),
            str(root / "CODEOWNERS"),
            str(root / ".github" / "CODEOWNERS"),
            str(root / "docs" / "CODEOWNERS"),
        ]
        for rel in self.workflow_dirs():
            workflow_dir = (root / rel).resolve()
            values.append(str(workflow_dir))
            if workflow_dir.is_dir():
                for child in sorted(workflow_dir.iterdir()):
                    if child.suffix.lower() in {".yml", ".yaml"}:
                        values.append(str(child.resolve()))
        for package_json in resolve_workspace_package_jsons(root):
            values.append(str(package_json))
            if package_json.parent != root:
                values.append(str(package_json.parent))
        return unique_sorted(values)


def parse_simple_list_block(lines: list[str], start: int, indent: int) -> tuple[list[str], int]:
    values: list[str] = []
    index = start
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        current_indent = len(raw) - len(raw.lstrip(" "))
        if current_indent <= indent:
            break
        item = raw[current_indent:]
        if not item.startswith("- "):
            index += 1
            continue
        value = item[2:].strip().strip("'\"")
        if value:
            values.append(value)
        index += 1
    return values, index


def parse_inline_list(raw: str) -> list[str]:
    raw = raw.strip()
    if not raw.startswith("[") or not raw.endswith("]"):
        return []
    inner = raw[1:-1].strip()
    if not inner:
        return []
    values: list[str] = []
    for item in inner.split(","):
        value = item.strip().strip("'\"")
        if value:
            values.append(value)
    return values


def parse_policy_workflow_paths(policy_path: Path) -> list[str]:
    if not policy_path.is_file():
        return []
    lines = policy_path.read_text(encoding="utf-8").splitlines()
    github_indent: int | None = None
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if github_indent is None:
            if stripped == "github:":
                github_indent = indent
            index += 1
            continue
        if indent <= github_indent:
            break
        if stripped.startswith("workflowPaths:"):
            remainder = stripped.split(":", 1)[1].strip()
            if remainder:
                return parse_inline_list(remainder)
            values, _ = parse_simple_list_block(lines, index + 1, indent)
            return values
        index += 1
    return []


def parse_workspace_patterns(workspace_file: Path) -> list[str]:
    if not workspace_file.is_file():
        return []
    lines = workspace_file.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if stripped.startswith("packages:"):
            remainder = stripped.split(":", 1)[1].strip()
            if remainder:
                return parse_inline_list(remainder)
            values, _ = parse_simple_list_block(lines, index + 1, indent)
            return values
        index += 1
    return []


def resolve_workspace_package_jsons(repo_root: Path) -> list[Path]:
    workspace_file = repo_root / "pnpm-workspace.yaml"
    patterns = parse_workspace_patterns(workspace_file)
    if not patterns:
        return [repo_root / "package.json"]

    included: dict[Path, bool] = {}
    ordered: list[Path] = []
    for pattern in patterns:
        exclude = pattern.startswith("!")
        value = pattern[1:] if exclude else pattern
        matches = sorted(repo_root.glob(value))
        for match in matches:
            candidate = match if match.is_dir() else match.parent
            try:
                candidate.relative_to(repo_root)
            except ValueError:
                continue
            candidate = candidate.resolve()
            if exclude:
                included.pop(candidate, None)
                continue
            if candidate in included:
                continue
            included[candidate] = True
            ordered.append(candidate)

    result: list[Path] = [repo_root / "package.json"]
    seen = {str((repo_root / "package.json").resolve())}
    for directory in ordered:
        if directory not in included:
            continue
        package_json = (directory / "package.json").resolve()
        if str(package_json) in seen:
            continue
        seen.add(str(package_json))
        result.append(package_json)
    return result


def relative_to_repo(repo_root: Path | None, file_path: str | None) -> str:
    if repo_root is None or not file_path:
        return ""
    path = Path(file_path)
    if not path.is_absolute():
        path = (repo_root / path).resolve()
    else:
        path = path.resolve()
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return ""
    return rel.as_posix()


def classify_path(repo_root: Path | None, workflow_dirs: list[str], file_path: str | None) -> list[str]:
    rel = relative_to_repo(repo_root, file_path)
    if not rel:
        return []
    scopes: list[str] = []
    if rel == "pnpm-workspace.yaml":
        scopes.append("workspace")
    if rel == ".guard/policy.yaml":
        scopes.append("policy")
    if rel == "pnpm-lock.yaml" or rel.endswith("/package.json") or rel == "package.json":
        scopes.append("deps")
    if rel in {"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}:
        scopes.append("workflows")
    for workflow_dir in workflow_dirs or DEFAULT_WORKFLOW_DIRS:
        prefix = workflow_dir.rstrip("/") + "/"
        if rel.startswith(prefix) and rel.endswith((".yml", ".yaml")):
            if "workflows" not in scopes:
                scopes.append("workflows")
    return scopes


def parse_scan_result(data: dict[str, Any] | None) -> tuple[str, int, int]:
    findings = []
    if isinstance(data, dict):
        findings = data.get("findings") or []
    blocking = sum(1 for finding in findings if finding.get("blocking") and not finding.get("muted"))
    warnings = sum(1 for finding in findings if not finding.get("blocking") and not finding.get("muted"))
    if blocking:
        return "blocking", blocking, warnings
    if warnings:
        return "warning", 0, warnings
    return "clean", 0, 0


def parse_lint_result(data: dict[str, Any] | None) -> tuple[str, int, int]:
    issues = []
    if isinstance(data, dict):
        issues = data.get("issues") or []
    blocking = sum(1 for issue in issues if issue.get("severity") == "error")
    warnings = sum(1 for issue in issues if issue.get("severity") != "error")
    if blocking:
        return "blocking", blocking, warnings
    if warnings:
        return "warning", 0, warnings
    return "clean", 0, 0


def worse_status(a: str, b: str) -> str:
    order = {"clean": 0, "warning": 1, "blocking": 2, "error": 3}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def summarize_scope(scope: str, status: str, blocking: int, warnings: int) -> str:
    if status == "blocking":
        return f"Guard {scope} review found {blocking} blocking finding(s)."
    if status == "warning":
        return f"Guard {scope} review found {warnings} warning finding(s)."
    return f"Guard {scope} review is clean."


def summarize_policy(status: str, blocking: int, warnings: int) -> str:
    if status == "blocking":
        return f"Guard policy review found {blocking} blocking issue(s)."
    if status == "warning":
        return f"Guard policy review found {warnings} warning issue(s)."
    return "Guard policy review is clean."


def update_scope_from_scan(
    runtime: Runtime,
    scope: str,
    *,
    status: str,
    blocking: int,
    warnings: int,
    trigger: str,
    report_path: Path | None,
    files: list[str] | None = None,
    error: str = "",
    needs_attention: bool = False,
) -> None:
    if runtime.state is None:
        return
    target = runtime.scope_state(scope)
    target["status"] = status
    target["pending"] = False
    target["blocking_count"] = blocking
    target["warning_count"] = warnings
    target["last_trigger"] = trigger
    target["last_run_at"] = now_utc()
    target["report_path"] = str(report_path) if report_path else ""
    target["last_files"] = files or []
    target["last_error"] = error
    target["needs_attention"] = bool(needs_attention and status == "blocking")


def mark_pending(runtime: Runtime, scope: str, trigger: str) -> None:
    if runtime.state is None:
        return
    target = runtime.scope_state(scope)
    target["pending"] = True
    target["last_trigger"] = trigger
    target["needs_attention"] = False


def extract_command(event: dict[str, Any]) -> str:
    tool_input = event.get("tool_input")
    if isinstance(tool_input, dict):
        command = tool_input.get("command")
        if isinstance(command, str):
            return command.strip()
    return ""


def extract_tool_file_path(event: dict[str, Any]) -> str:
    tool_input = event.get("tool_input")
    if isinstance(tool_input, dict):
        file_path = tool_input.get("file_path")
        if isinstance(file_path, str) and file_path.strip():
            return file_path
    tool_response = event.get("tool_response")
    if isinstance(tool_response, dict):
        file_path = tool_response.get("filePath")
        if isinstance(file_path, str) and file_path.strip():
            return file_path
    return ""


def command_scopes(command: str) -> list[str]:
    text = command.strip()
    if not text:
        return []
    if re.match(r"^corepack\s+use(\s|$)", text):
        return ["workspace"]
    if re.match(r"^(pnpm|npm)\s+(add|up|install|remove|update|uninstall)(\s|$)", text):
        return ["deps"]
    return []


def run_scan(
    runtime: Runtime,
    scope: str,
    *,
    trigger: str,
    files: list[str] | None = None,
    changed_files: bool = False,
) -> tuple[str, int, int, str]:
    assert runtime.repo_root is not None
    args = ["scan", "--root", str(runtime.repo_root), "--scope", scope, "--format", "json", "--no-color"]
    if files:
        args.extend(["--files", ",".join(files)])
    elif changed_files:
        args.append("--changed-files")
    report_path = runtime.report_path(scope)
    returncode, data, stderr = runtime.run_guard(args, report_name=scope)
    status, blocking, warnings = parse_scan_result(data)
    error = ""
    if data is None and returncode != 0:
        error = stderr or f"guard scan failed for scope {scope}"
        if changed_files:
            fallback_args = ["scan", "--root", str(runtime.repo_root), "--scope", scope, "--format", "json", "--no-color"]
            fallback_return, fallback_data, fallback_stderr = runtime.run_guard(
                fallback_args,
                report_name=f"{scope}-fallback",
            )
            if fallback_data is not None:
                data = fallback_data
                returncode = fallback_return
                stderr = fallback_stderr
                report_path = runtime.report_path(f"{scope}-fallback")
                status, blocking, warnings = parse_scan_result(data)
                error = ""
    update_scope_from_scan(
        runtime,
        scope,
        status=status if not error else "error",
        blocking=blocking,
        warnings=warnings,
        trigger=trigger,
        report_path=report_path,
        files=files,
        error=error,
        needs_attention=trigger in {"post_write", "post_bash"},
    )
    summary = summarize_scope(scope, status if not error else "warning", blocking, warnings)
    if error:
        summary = f"Guard {scope} review failed: {error}"
    return status if not error else "error", blocking, warnings, summary


def run_policy_review(runtime: Runtime, *, trigger: str, files: list[str] | None = None) -> tuple[str, int, int, str]:
    assert runtime.repo_root is not None
    lint_report_path = runtime.report_path("policy-lint")
    lint_args = ["policy", "lint", "--root", str(runtime.repo_root), "--format", "json", "--no-color"]
    _, lint_data, lint_stderr = runtime.run_guard(lint_args, report_name="policy-lint")
    lint_status, lint_blocking, lint_warnings = parse_lint_result(lint_data)

    scan_status, scan_blocking, scan_warnings, _ = run_scan(
        runtime,
        "policy",
        trigger=trigger,
        files=files,
    )

    combined_status = worse_status(scan_status, lint_status)
    blocking = max(runtime.scope_state("policy")["blocking_count"], lint_blocking)
    warnings = max(runtime.scope_state("policy")["warning_count"], lint_warnings)
    target = runtime.scope_state("policy")
    target["status"] = combined_status
    target["blocking_count"] = blocking
    target["warning_count"] = warnings
    target["last_run_at"] = now_utc()
    target["last_trigger"] = trigger
    target["pending"] = False
    target["needs_attention"] = combined_status == "blocking" and trigger in {"post_write", "post_bash"}
    target["last_files"] = files or []
    target["lint_report_path"] = str(lint_report_path) if lint_report_path else ""
    if lint_data is None and lint_stderr:
        target["last_error"] = lint_stderr
    summary = summarize_policy(combined_status, blocking, warnings)
    return combined_status, blocking, warnings, summary


def session_start(runtime: Runtime) -> dict[str, Any] | None:
    if runtime.repo_root is None:
        return None
    assert runtime.state is not None
    prior_session = runtime.state.get("session_id") or ""
    current_session = runtime.event.get("session_id") or ""
    if prior_session != current_session:
        runtime.clear_session_flags()
    runtime.state["session_id"] = current_session
    runtime.state["mode"] = runtime.mode
    runtime.state["watch_paths"] = runtime.compute_watch_paths()
    runtime.save_state()

    available, detail = runtime.guard_available()
    if not available:
        return {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": "Guard plugin idle for this repo: Guard CLI is not available. Set GUARD_BIN or add guard to PATH.",
            }
        }

    return {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": f"Guard active in {runtime.mode} mode for this repo. Focused reviews cover deps, workflows, policy, and workspace changes.",
        }
    }


def cwd_changed(runtime: Runtime) -> dict[str, Any]:
    if runtime.repo_root is None:
        return {"watchPaths": []}
    assert runtime.state is not None
    runtime.state["session_id"] = runtime.event.get("session_id") or runtime.state.get("session_id", "")
    runtime.state["mode"] = runtime.mode
    runtime.state["watch_paths"] = runtime.compute_watch_paths()
    runtime.save_state()
    return {"watchPaths": runtime.state["watch_paths"]}


def file_changed(runtime: Runtime) -> dict[str, Any]:
    if runtime.repo_root is None or runtime.state is None:
        return {"watchPaths": []}
    path = runtime.event.get("file_path")
    scopes = classify_path(runtime.repo_root, runtime.workflow_dirs(), path)
    for scope in scopes:
        mark_pending(runtime, scope, "file_changed")
    runtime.state["watch_paths"] = runtime.compute_watch_paths()
    runtime.save_state()
    return {"watchPaths": runtime.state["watch_paths"]}


def pre_bash(runtime: Runtime) -> dict[str, Any] | None:
    if runtime.repo_root is None or runtime.state is None:
        return None
    command = extract_command(runtime.event)
    scopes = command_scopes(command)
    if not scopes:
        return None

    blocking_scopes: list[str] = []
    pending_scopes: list[str] = []
    for scope in scopes:
        scope_state = runtime.scope_state(scope)
        if scope_state["status"] == "blocking" and scope_state["blocking_count"] > 0:
            blocking_scopes.append(scope)
        elif scope_state["pending"] and scope_state["last_trigger"] != "pre_bash":
            pending_scopes.append(scope)

    if runtime.mode == "observe":
        if blocking_scopes or pending_scopes:
            details = []
            if blocking_scopes:
                details.append("blocking findings in " + ", ".join(blocking_scopes))
            if pending_scopes:
                details.append("pending review in " + ", ".join(pending_scopes))
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": f"Guard note before `{command}`: " + "; ".join(details) + ".",
                }
            }
        return None

    if runtime.mode == "strict" and blocking_scopes:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Guard strict mode blocked this command because relevant blocking findings are still active.",
                "additionalContext": "Resolve the active Guard findings or rerun a focused review before retrying this command.",
            }
        }

    if blocking_scopes or pending_scopes:
        reason_parts: list[str] = []
        if blocking_scopes:
            reason_parts.append("relevant blocking findings are active")
        if pending_scopes:
            reason_parts.append("a focused review is still pending")
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": "Guard wants confirmation before this sensitive command because " + " and ".join(reason_parts) + ".",
                "additionalContext": "Relevant Guard scopes: " + ", ".join(sorted(set(blocking_scopes + pending_scopes))) + ".",
            }
        }

    return None


def post_write(runtime: Runtime) -> dict[str, Any] | None:
    if runtime.repo_root is None or runtime.state is None:
        return None
    available, _ = runtime.guard_available()
    if not available:
        return None

    file_path = extract_tool_file_path(runtime.event)
    scopes = classify_path(runtime.repo_root, runtime.workflow_dirs(), file_path)
    if not scopes:
        return None

    rel = relative_to_repo(runtime.repo_root, file_path)
    messages: list[str] = []
    for scope in scopes:
        if scope == "policy":
            status, _, _, summary = run_policy_review(runtime, trigger="post_write", files=[rel] if rel else None)
        else:
            status, _, _, summary = run_scan(runtime, scope, trigger="post_write", files=[rel] if rel else None)
        if status in {"blocking", "warning", "error"}:
            messages.append(summary)

    runtime.state["watch_paths"] = runtime.compute_watch_paths()
    runtime.save_state()
    if not messages:
        return None
    return {"additionalContext": " ".join(messages)}


def post_bash(runtime: Runtime) -> dict[str, Any] | None:
    if runtime.repo_root is None or runtime.state is None:
        return None
    available, _ = runtime.guard_available()
    if not available:
        return None
    command = extract_command(runtime.event)
    scopes = command_scopes(command)
    if not scopes:
        return None

    messages: list[str] = []
    for scope in scopes:
        status, _, _, summary = run_scan(runtime, scope, trigger="post_bash", changed_files=True)
        if status in {"blocking", "warning", "error"}:
            messages.append(summary)

    runtime.state["watch_paths"] = runtime.compute_watch_paths()
    runtime.save_state()
    if not messages:
        return None
    return {"additionalContext": " ".join(messages)}


def stop_summary(runtime: Runtime) -> dict[str, Any] | None:
    if runtime.repo_root is None or runtime.state is None:
        return None
    if runtime.event.get("stop_hook_active"):
        return None
    if runtime.mode == "observe":
        return None

    blocking_scopes: list[str] = []
    pending_scopes: list[str] = []
    for scope in SCOPES:
        scope_state = runtime.scope_state(scope)
        if scope_state["status"] == "blocking" and scope_state["needs_attention"]:
            blocking_scopes.append(scope)
        if runtime.mode == "strict" and scope_state["pending"] and scope_state["last_trigger"] in {"file_changed", "pre_bash"}:
            pending_scopes.append(scope)

    if runtime.mode == "balanced" and blocking_scopes:
        for scope in blocking_scopes:
            runtime.scope_state(scope)["needs_attention"] = False
        runtime.save_state()
        return {
            "decision": "block",
            "reason": "Guard found blocking results in " + ", ".join(blocking_scopes) + ". Address them or explicitly choose to continue.",
        }

    if runtime.mode == "strict" and (blocking_scopes or pending_scopes):
        for scope in blocking_scopes:
            runtime.scope_state(scope)["needs_attention"] = False
        runtime.save_state()
        parts: list[str] = []
        if blocking_scopes:
            parts.append("blocking findings in " + ", ".join(blocking_scopes))
        if pending_scopes:
            parts.append("pending sensitive reviews in " + ", ".join(pending_scopes))
        return {
            "decision": "block",
            "reason": "Guard strict mode will not stop with " + " and ".join(parts) + ".",
        }

    return None


COMMANDS = {
    "session-start": session_start,
    "cwd-changed": cwd_changed,
    "file-changed": file_changed,
    "pre-bash": pre_bash,
    "post-write": post_write,
    "post-bash": post_bash,
    "stop-summary": stop_summary,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in COMMANDS:
        available = ", ".join(sorted(COMMANDS))
        raise SystemExit(f"usage: guard_hook.py <{available}>")
    event = read_event()
    runtime = Runtime(event=event, command_name=argv[1])
    result = COMMANDS[argv[1]](runtime)
    return emit(result)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
