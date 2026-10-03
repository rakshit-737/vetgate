"""Cross-convention pre-flight inventory.

Finds everything that would auto-execute or be auto-loaded the moment an AI coding
agent or agentic IDE opens/trusts a workspace — across *all* the conventions at once
(Claude Code, Cursor, Windsurf, VS Code, devcontainers, AGENTS.md, Copilot, git
hooks, npm/pip lifecycle scripts, direnv) — plus the env-var exec vectors most
scanners miss.

`analyze_file(relpath, content, ref)` is the shared unit so the exact same logic
runs over the working tree *and* over blobs on every git ref (see refs.py).
"""
from __future__ import annotations

import json
import os
import posixpath
import re
from typing import List, Optional

from vetgate import patterns as P
from vetgate.instructions import analyze_text
from vetgate.model import Finding, Severity

MAX_BYTES = 512 * 1024  # don't read giant files into memory

# Paths treated as agent/IDE execution or instruction surfaces. Used to pre-filter
# which blobs to pull when sweeping git refs.
SENSITIVE_BASENAMES = {
    "settings.json", "settings.local.json", ".mcp.json", "mcp.json",
    "tasks.json", "devcontainer.json", ".devcontainer.json", ".cursorrules",
    "claude.md", "agents.md", "copilot-instructions.md", "package.json",
    "setup.py", ".envrc", "soul.md", "memory.md", ".aider.conf.yml",
    ".windsurfrules",
}
# git hook names whose bodies we analyze (as scripts) wherever they appear.
GIT_HOOK_NAMES = {
    "pre-commit", "pre-push", "pre-merge-commit", "post-checkout", "post-merge",
    "post-commit", "prepare-commit-msg", "commit-msg", "pre-rebase", "post-rewrite",
    "pre-applypatch", "post-applypatch", "applypatch-msg", "post-index-change",
}
SENSITIVE_DIR_HINTS = (".claude", ".cursor", ".vscode", ".devcontainer",
                       ".github", ".githooks", ".windsurf")
INSTRUCTION_SUFFIXES = (".md", ".mdc", ".mdx", ".txt", ".rules")


def is_sensitive_path(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    base = posixpath.basename(rel).lower()
    if base in SENSITIVE_BASENAMES:
        return True
    parts = rel.lower().split("/")
    if any(h in parts for h in SENSITIVE_DIR_HINTS):
        return True
    if base in ("claude.md", "agents.md") or base.endswith(".cursorrules"):
        return True
    return False


# --------------------------------------------------------------------------- #
#  JSON(C) helpers                                                            #
# --------------------------------------------------------------------------- #
_TRAILING_COMMA_RX = re.compile(r",(\s*[}\]])")
_PARSE_FAIL = object()  # sentinel: a known config file we could NOT parse (fail closed)


def _strip_jsonc_comments(text: str) -> str:
    """Remove // and /* */ comments WITHOUT touching comment-like text inside strings.

    The naive regex approach ate `//` inside URLs (`"https://…"`), corrupting the JSON and
    making the whole file silently un-parsed — a fail-open an attacker triggers with one
    comment. This is string-aware so that can't happen.
    """
    out = []
    i, n = 0, len(text)
    in_str = esc = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c); i += 1; continue
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(c); i += 1
    return "".join(out)


def _loads_jsonc(text: str):
    """Parse JSON or JSONC. Returns the object, or the _PARSE_FAIL sentinel if neither
    strict JSON nor comment-stripped JSONC parses — so callers can fail CLOSED."""
    text = text.lstrip("﻿")
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        pass
    cleaned = _TRAILING_COMMA_RX.sub(r"\1", _strip_jsonc_comments(text))
    try:
        return json.loads(cleaned)
    except (ValueError, RecursionError):
        return _PARSE_FAIL


def _parsefail_finding(rel, ref, surface) -> Finding:
    return Finding(
        id="config.unparseable", title=f"Unparseable config: {posixpath.basename(rel)}",
        severity=Severity.MEDIUM, surface=surface, path=rel, ref=ref,
        detail="A known agent/IDE config file could not be parsed, so its contents were NOT "
               "vetted — yet the editor/agent may still act on it. Malformed-but-tolerated "
               "config is a known evasion.",
        trigger="loaded by the agent/IDE regardless of whether vetgate could read it",
        recommendation="Open and review this file by hand.", tags=["parse-fail"])


def _cfg(text, rel, ref, surface):
    """Parse a config and fail closed. Returns (dict | None, findings-to-emit-if-None)."""
    d = _loads_jsonc(text)
    if d is _PARSE_FAIL:
        return None, [_parsefail_finding(rel, ref, surface)]
    if not isinstance(d, dict):
        return None, []
    return d, []


def _walk_strings(obj, key_filter=None):
    """Yield (key, value) for every string value in a nested dict/list."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and (key_filter is None or key_filter(k)):
                yield k, v
            else:
                yield from _walk_strings(v, key_filter)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v, key_filter)


# --------------------------------------------------------------------------- #
#  Per-surface analyzers                                                       #
# --------------------------------------------------------------------------- #
def _claude_settings(rel, text, ref) -> List[Finding]:
    out: List[Finding] = []
    data, pf = _cfg(text, rel, ref, "claude-code")
    if data is None:
        return pf
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, spec in hooks.items():
            cmds = [v for _, v in _walk_strings(spec, lambda k: k == "command")]
            # Every one of these events auto-runs with no per-call confirmation.
            auto = event in ("SessionStart", "UserPromptSubmit", "PreToolUse",
                             "PostToolUse", "Notification", "PreCompact", "Stop",
                             "SubagentStop", "SessionEnd")
            trig = ("runs automatically when the Claude Code session starts"
                    if event == "SessionStart" else
                    (f"runs automatically on the {event} event" if auto
                     else f"runs on the {event} event"))
            for cmd in cmds:
                danger = P.command_danger(cmd)
                if danger == "CRITICAL":
                    out.append(Finding(
                        id="claude.hook.rce", title="Claude Code hook fetches & executes code",
                        severity=Severity.CRITICAL, surface="claude-code", path=rel, ref=ref,
                        detail="Hook command pipes downloaded content into an interpreter or decodes-and-runs.",
                        evidence=_clip(cmd), trigger=trig,
                        recommendation="Remove immediately; this is the keyv-worm persistence pattern.",
                        tags=["hook", "rce"]))
                    continue
                # Severity = how auto-running it is × how opaque the command is.
                if danger == "HIGH":
                    sev = Severity.HIGH
                elif auto and P.hook_runs_arbitrary(cmd):
                    sev = Severity.HIGH          # auto-runs a repo script / opaque code
                elif auto:
                    sev = Severity.MEDIUM        # auto-runs, but a known dev tool
                else:
                    sev = Severity.LOW
                out.append(Finding(
                    id="claude.hook", title=f"Claude Code hook ({event}) runs a command",
                    severity=sev, surface="claude-code", path=rel, ref=ref,
                    detail=f"A `{event}` hook executes a command inside Claude Code.",
                    evidence=_clip(cmd), trigger=trig,
                    recommendation="Confirm you wrote this hook. Hooks run with your shell's privileges.",
                    tags=["hook", "auto-exec"]))
    if data.get("enableAllProjectMcpServers") is True:
        out.append(Finding(
            id="claude.mcp_autoenable", title="Repo auto-enables all its MCP servers",
            severity=Severity.MEDIUM, surface="claude-code", path=rel, ref=ref,
            detail="`enableAllProjectMcpServers` trusts every MCP server the repo declares without prompting.",
            trigger="MCP servers start when the project is opened",
            recommendation="Enable MCP servers explicitly after reviewing each.", tags=["mcp"]))
    return out


def _mcp_config(rel, text, ref) -> List[Finding]:
    out: List[Finding] = []
    data, pf = _cfg(text, rel, ref, "mcp")
    if data is None:
        return pf
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        return out
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        cmd = spec.get("command", "")
        args = spec.get("args", []) if isinstance(spec.get("args"), list) else []
        url = spec.get("url") or spec.get("endpoint") or ""
        argstr = " ".join(str(a) for a in args)
        if url and str(url).startswith(("http://", "https://")):
            out.append(Finding(
                id="mcp.remote", title=f"Remote MCP server '{name}'",
                severity=Severity.MEDIUM, surface="mcp", path=rel, ref=ref,
                detail=f"Declares a remote MCP server at {url}. Remote servers can change the tools "
                       "and tool *descriptions* they return after you approve them (metadata poisoning).",
                evidence=str(url), trigger="connected when the agent starts with this config",
                recommendation="Pin and monitor remote MCP servers; prefer vetted local ones.",
                tags=["mcp", "remote"]))
        if re.search(r"\b(npx|uvx|bunx)\b", str(cmd) + " " + argstr) and "-y" in argstr.split():
            out.append(Finding(
                id="mcp.npx_auto", title=f"MCP server '{name}' auto-installs a package",
                severity=Severity.LOW, surface="mcp", path=rel, ref=ref,
                detail="Uses `npx -y`/`uvx` to fetch and run a package with no confirmation.",
                evidence=_clip(f"{cmd} {argstr}"), trigger="package fetched & executed on agent start",
                recommendation="Pin exact versions; vendor the server instead of auto-fetching.",
                tags=["mcp", "supply-chain"]))
        env = spec.get("env", {})
        if isinstance(env, dict):
            leaked = [k for k in env if re.search(r"TOKEN|KEY|SECRET|PASSWORD", k, re.I)]
            if leaked:
                out.append(Finding(
                    id="mcp.env_secrets", title=f"MCP server '{name}' is handed secret env vars",
                    severity=Severity.HIGH, surface="mcp", path=rel, ref=ref,
                    detail="Secret-looking env vars (" + ", ".join(leaked[:4]) + ") are passed to the server.",
                    evidence=", ".join(leaked[:4]), trigger="secrets exposed to the server process on start",
                    recommendation="Verify the server is trusted before giving it credentials.",
                    tags=["mcp", "secrets"]))
    return out


def _vscode_tasks(rel, text, ref) -> List[Finding]:
    out: List[Finding] = []
    data, pf = _cfg(text, rel, ref, "vscode")
    if data is None:
        return pf
    for task in data.get("tasks", []) if isinstance(data.get("tasks"), list) else []:
        if not isinstance(task, dict):
            continue
        ro = task.get("runOptions")
        runon = ro.get("runOn") if isinstance(ro, dict) else None
        cmd = task.get("command", "")
        argv = task.get("args", [])
        full = _clip((str(cmd) + " " + " ".join(map(str, argv))).strip()) if cmd else task.get("label", "")
        if runon == "folderOpen":
            out.append(Finding(
                id="vscode.task.folderopen", title="VS Code task runs on folder open",
                severity=Severity.HIGH, surface="vscode", path=rel, ref=ref,
                detail="A task with `runOn: folderOpen` executes automatically the instant the folder is opened in VS Code.",
                evidence=full, trigger="runs automatically when the folder is opened in VS Code",
                recommendation="This is the keyv-worm auto-run vector — confirm you created this task.",
                tags=["vscode", "auto-exec"]))
    return out


def _devcontainer(rel, text, ref) -> List[Finding]:
    out: List[Finding] = []
    data, pf = _cfg(text, rel, ref, "devcontainer")
    if data is None:
        return pf
    for key in ("initializeCommand", "onCreateCommand", "updateContentCommand",
                "postCreateCommand", "postStartCommand", "postAttachCommand"):
        if key in data:
            val = data[key]
            val = val if isinstance(val, str) else json.dumps(val)
            danger = P.command_danger(val)
            sev = Severity.from_str(danger) if danger else Severity.LOW
            out.append(Finding(
                id="devcontainer.lifecycle", title=f"Dev container {key}",
                severity=sev, surface="devcontainer", path=rel, ref=ref,
                detail=f"`{key}` runs a command when the dev container is built/opened."
                       + (" It fetches from the network / touches secrets / evals code." if danger else ""),
                evidence=_clip(val),
                trigger="runs automatically when the dev container is created/started",
                recommendation="Review lifecycle commands before reopening in container.",
                tags=["devcontainer", "auto-exec"]))
    return out


def _package_json(rel, text, ref) -> List[Finding]:
    out: List[Finding] = []
    data, pf = _cfg(text, rel, ref, "npm")
    if data is None:
        return pf
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return out
    AUTORUN = {"preinstall", "install", "postinstall", "prepare",
               "prepublish", "prepublishOnly", "postpublish", "preprepare"}
    for name, cmd in scripts.items():
        if name not in AUTORUN:
            continue
        danger = P.command_danger(str(cmd))
        # Ordinary lifecycle commands are noted (LOW); only risky content escalates.
        out.append(Finding(
            id="npm.lifecycle", title=f"npm lifecycle script '{name}'",
            severity=Severity.LOW, surface="npm", path=rel, ref=ref,
            detail=f"`{name}` runs automatically during `npm install`.",
            evidence=_clip(str(cmd)),
            trigger="runs automatically on `npm install`",
            recommendation="Review it, or install untrusted deps with `--ignore-scripts`.",
            tags=["npm", "auto-exec"]))
        if danger == "CRITICAL":
            out.append(Finding(
                id="npm.lifecycle.rce", title=f"npm '{name}' fetches & executes code",
                severity=Severity.CRITICAL, surface="npm", path=rel, ref=ref,
                detail="Lifecycle script pipes downloaded content into a shell or runs an encoded blob.",
                evidence=_clip(str(cmd)), trigger="runs automatically on `npm install`",
                recommendation="Do not install. This is a preinstall-malware pattern.", tags=["npm", "rce"]))
        elif danger == "HIGH":
            out.append(Finding(
                id="npm.lifecycle.suspicious", title=f"npm '{name}' does network/secret/eval work",
                severity=Severity.HIGH, surface="npm", path=rel, ref=ref,
                detail="Lifecycle script fetches from the network, touches secrets, or evals code.",
                evidence=_clip(str(cmd)), trigger="runs automatically on `npm install`",
                recommendation="Confirm this is expected; it is a common exfiltration foothold.",
                tags=["npm", "suspicious"]))
    return out


def _envrc(rel, text, ref) -> List[Finding]:
    out = [Finding(
        id="direnv.envrc", title="direnv .envrc auto-executes",
        severity=Severity.LOW, surface="direnv", path=rel, ref=ref,
        detail="`.envrc` runs shell on `cd` into the directory once direnv is allowed.",
        trigger="runs when you cd into the repo (if direnv is enabled)",
        recommendation="Read `.envrc` fully before `direnv allow`.", tags=["direnv", "auto-exec"])]
    out += _exec_env_findings(rel, text, ref, "direnv")
    out += analyze_text(text, rel, surface="direnv", ref=ref)
    return out


def _exec_env_findings(rel, text, ref, surface) -> List[Finding]:
    out = []
    for var, off in P.find_exec_env_assignments(text):
        out.append(Finding(
            id="env.exec_var", title=f"Sets code-execution env var {var}",
            severity=Severity.HIGH, surface=surface, path=rel, ref=ref,
            line=P.line_of(text, off),
            detail=f"Assigning {var} can inject code into shells/interpreters/the dynamic linker.",
            evidence=var, trigger="takes effect in any process spawned after it is set",
            recommendation=f"Confirm why {var} is set here; this is a stealth exec vector.",
            tags=["env", "auto-exec"]))
    return out


def _vscode_settings(rel, text, ref) -> List[Finding]:
    out: List[Finding] = []
    data, pf = _cfg(text, rel, ref, "vscode")
    if data is None:
        return pf
    if data.get("security.workspace.trust.enabled") is False:
        out.append(Finding(
            id="vscode.trust_disabled", title="VS Code Workspace Trust disabled by the repo",
            severity=Severity.MEDIUM, surface="vscode", path=rel, ref=ref,
            detail="The repo ships a setting that turns off Workspace Trust, removing VS Code's own guardrail.",
            trigger="applied when the folder is opened", tags=["vscode"],
            recommendation="Ignore repo-supplied trust settings; keep Workspace Trust on."))
    # terminal.integrated.env.* can set exec env vars
    out += _exec_env_findings(rel, text, ref, "vscode")
    return out


def _script_body(rel, text, ref, surface, trigger) -> List[Finding]:
    """Analyze a shell/hook script body: escalate lines that fetch/pipe/eval/touch
    secrets, plus the usual instruction-file checks (hidden unicode, base64, creds)."""
    out: List[Finding] = []
    worst = None
    worst_line = worst_ev = None
    for i, line in enumerate(text.splitlines(), 1):
        d = P.command_danger(line)
        if d:
            sev = Severity.from_str(d)
            if worst is None or int(sev) > int(worst):
                worst, worst_line, worst_ev = sev, i, line.strip()
    if worst is not None:
        out.append(Finding(
            id="script.danger", title=f"{surface} script fetches/executes code",
            severity=worst, surface=surface, path=rel, ref=ref, line=worst_line,
            detail="A line in this script pipes downloaded content into an interpreter, "
                   "decodes-and-runs, touches secrets, or evals code.",
            evidence=_clip(worst_ev or ""), trigger=trigger,
            recommendation="Review the script; hooks are a common persistence/exfil spot.",
            tags=[surface, "script", "auto-exec"]))
    out += analyze_text(text, rel, surface=surface, ref=ref)
    return out


# path -> analyzer dispatch
def analyze_file(rel: str, content: str, ref: str = "working-tree") -> List[Finding]:
    rel_norm = rel.replace("\\", "/")
    base = posixpath.basename(rel_norm).lower()
    parts = rel_norm.lower().split("/")
    out: List[Finding] = []

    if base in ("settings.json", "settings.local.json") and ".claude" in parts:
        out += _claude_settings(rel_norm, content, ref)
    elif base in (".mcp.json", "mcp.json"):
        out += _mcp_config(rel_norm, content, ref)
    elif base == "tasks.json" and ".vscode" in parts:
        out += _vscode_tasks(rel_norm, content, ref)
    elif base == "settings.json" and ".vscode" in parts:
        out += _vscode_settings(rel_norm, content, ref)
    elif base in ("devcontainer.json", ".devcontainer.json"):
        out += _devcontainer(rel_norm, content, ref)
    elif ".githooks" in parts or (base in GIT_HOOK_NAMES and "hooks" in parts):
        out += _script_body(rel_norm, content, ref, "git",
                            "runs on the corresponding git event")
    elif base == "package.json":
        out += _package_json(rel_norm, content, ref)
    elif base == ".envrc":
        out += _envrc(rel_norm, content, ref)
    elif base == "setup.py":
        out.append(Finding(
            id="pip.setup_py", title="setup.py executes on source install",
            severity=Severity.LOW, surface="pip", path=rel_norm, ref=ref,
            detail="`setup.py` runs arbitrary Python during `pip install .`/`pip install <sdist>`.",
            trigger="runs on `pip install` from source",
            recommendation="Prefer wheels; review setup.py for os.system/subprocess calls.",
            tags=["pip"]))
        out += analyze_text(content, rel_norm, surface="pip", ref=ref)

    # Instruction-ish files (also covers CLAUDE.md, AGENTS.md, rules, copilot, MEMORY/SOUL)
    is_instr = (
        base in ("claude.md", "agents.md", "memory.md", "soul.md",
                 "copilot-instructions.md", ".cursorrules", ".windsurfrules",
                 ".aider.conf.yml")
        or (".cursor" in parts and rel_norm.lower().endswith((".md", ".mdc", ".rules")))
        or (".claude" in parts and base.endswith((".md", ".mdc")))
        or (".github" in parts and base == "copilot-instructions.md")
        or (".windsurf" in parts and rel_norm.lower().endswith((".md", ".mdc", ".rules")))
    )
    if is_instr:
        base_sev = Finding(
            id="instr.autoload", title=f"Agent-loaded instruction file ({base})",
            severity=Severity.INFO, surface="instruction-file", path=rel_norm, ref=ref,
            detail="Auto-loaded into the agent's context; its text can steer the agent.",
            trigger="read into the agent's context automatically", tags=["instruction"])
        out.append(base_sev)
        out += analyze_text(content, rel_norm, surface="instruction-file", ref=ref)
    return out


# --------------------------------------------------------------------------- #
#  Working-tree driver                                                         #
# --------------------------------------------------------------------------- #
def _clip(s: str, n: int = 140) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _read(path: str) -> Optional[str]:
    try:
        if os.path.getsize(path) > MAX_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _oversize(path: str) -> bool:
    try:
        return os.path.getsize(path) > MAX_BYTES
    except OSError:
        return False


def _oversize_finding(rel: str) -> Finding:
    return Finding(
        id="config.oversize", title=f"Oversized config: {posixpath.basename(rel)}",
        severity=Severity.HIGH, surface="config", path=rel, ref="working-tree",
        detail=f"A known agent/IDE config file exceeds {MAX_BYTES} bytes and was NOT vetted — "
               "padding is a known evasion, yet the editor/agent may still act on it.",
        trigger="loaded by the agent/IDE regardless of whether vetgate could read it",
        recommendation="Open and review this file by hand.", tags=["parse-fail"])


def scan_tree(root: str) -> List[Finding]:
    """Scan the working tree on disk (the checked-out files)."""
    root = os.path.abspath(root)
    findings: List[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Skip the live .git object store but handle hooks/config explicitly below.
        if os.path.basename(dirpath) == ".git":
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".venv", "venv")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if not is_sensitive_path(rel):
                continue
            content = _read(full)
            if content is None:
                if _oversize(full):
                    findings.append(_oversize_finding(rel.replace(os.sep, "/")))
                continue
            findings += analyze_file(rel, content, ref="working-tree")

    findings += _git_hooks_on_disk(root)
    return findings


def _git_hooks_on_disk(root: str) -> List[Finding]:
    out: List[Finding] = []
    gitdir = os.path.join(root, ".git")
    # core.hooksPath pointing inside the repo
    cfg = os.path.join(gitdir, "config")
    if os.path.isfile(cfg):
        txt = _read(cfg) or ""
        m = re.search(r"hookspath\s*=\s*(.+)", txt, re.I)
        if m:
            out.append(Finding(
                id="git.hookspath", title="git core.hooksPath is set",
                severity=Severity.HIGH, surface="git", path=".git/config",
                detail=f"core.hooksPath = {m.group(1).strip()} — git will run hooks from this path on git operations.",
                evidence=m.group(1).strip(), trigger="runs on git commit/checkout/merge etc.",
                recommendation="Confirm the hooks path; attackers repoint it into the repo.",
                tags=["git", "auto-exec"]))
    hooksdir = os.path.join(gitdir, "hooks")
    if os.path.isdir(hooksdir):
        for fn in os.listdir(hooksdir):
            if fn.endswith(".sample"):
                continue
            full = os.path.join(hooksdir, fn)
            # os.access(X_OK) is always True on Windows, so also treat a known hook
            # name as active there; analyze the body either way.
            if os.path.isfile(full) and (os.access(full, os.X_OK) or os.name == "nt"):
                out.append(Finding(
                    id="git.hook", title=f"Active git hook: {fn}",
                    severity=Severity.HIGH, surface="git", path=f".git/hooks/{fn}",
                    detail=f"An executable, non-sample git hook ({fn}) runs on the corresponding git event.",
                    trigger=f"runs on the git {fn} event",
                    recommendation="Review the hook body; git hooks are a common persistence spot.",
                    tags=["git", "auto-exec"]))
                out += _script_body(f".git/hooks/{fn}", _read(full) or "",
                                    "working-tree", "git", f"runs on the git {fn} event")
    # committed .githooks dir
    ghooks = os.path.join(root, ".githooks")
    if os.path.isdir(ghooks):
        out.append(Finding(
            id="git.githooks_dir", title="Committed .githooks/ directory",
            severity=Severity.MEDIUM, surface="git", path=".githooks/",
            detail="Repo ships a .githooks/ dir; combined with core.hooksPath it auto-runs on git events.",
            trigger="runs on git events if core.hooksPath points here",
            recommendation="Inspect each hook before enabling.", tags=["git"]))
    return out
