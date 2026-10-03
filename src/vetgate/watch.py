"""Personal-config watchdog — the flagship wedge.

Static repo scanners tell you whether a repo is safe to *open*. They say nothing
once it is already trusted and your agent is running. The real 2026 incidents
(keyv worm planting `.claude/settings.json` SessionStart hooks; self-propagating
instructions rewriting CLAUDE.md/MEMORY.md) happen *to your own machine config*,
after the fact, and git never sees `~/.claude`.

`vetgate baseline` records a SIGNED snapshot of your own agent config; `vetgate
watch` re-reads it and produces a *semantic* diff — "a new SessionStart hook
appeared", "+3 imperative instructions in CLAUDE.md", "a credential path was added"
— with a best-effort "was this you or the agent?" attribution and a timestamp. The
HMAC signature means the watchdog can tell you if its own baseline was tampered
with.

No GitHub query for a tool like this returned anything: this is the unowned wedge.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import time
from typing import Dict, List, Optional

from vetgate.model import Finding, Severity
from vetgate.surfaces import MAX_BYTES, analyze_file

VETGATE_HOME = os.path.expanduser("~/.vetgate")
BASELINE_PATH = os.path.join(VETGATE_HOME, "baseline.json")
SIG_PATH = BASELINE_PATH + ".sig"
KEY_PATH = os.path.join(VETGATE_HOME, "key")

# Directories/files that hold agent & editor configuration and instructions.
DEFAULT_ROOTS = [
    "~/.claude", "~/.cursor", "~/.vscode", "~/.codex", "~/.windsurf",
    "~/.config/claude", "~/.config/Code/User", "~/.aider.conf.yml",
    "~/Library/LaunchAgents", "~/.config/systemd/user",
    "~/.config/autostart",
]

# Files that agents themselves commonly write — a change here is "more likely the agent".
AGENT_MANAGED = {
    "settings.local.json", "memory.md", "soul.md", ".aider.chat.history.md",
    "history.jsonl", "mcp.json", ".mcp.json", "claude.md", "agents.md",
}

# Map finding-id -> human phrase for the semantic diff line.
_PHRASE = {
    "claude.hook": "agent hook",
    "claude.hook.rce": "fetch-and-execute hook",
    "claude.mcp_autoenable": "auto-enable-all-MCP setting",
    "mcp.remote": "remote MCP server",
    "mcp.npx_auto": "auto-installing MCP server",
    "mcp.env_secrets": "MCP server given secrets",
    "vscode.task.folderopen": "run-on-open VS Code task",
    "devcontainer.lifecycle": "dev-container lifecycle command",
    "npm.lifecycle": "npm lifecycle script",
    "npm.lifecycle.rce": "fetch-and-execute npm script",
    "env.exec_var": "code-execution env var",
    "instr.imperative": "imperative instruction",
    "instr.pipe_to_shell": "download-and-run one-liner",
    "instr.hidden.bidi-override": "hidden bidi character",
    "instr.hidden.unicode-tag": "hidden tag-block character",
    "instr.hidden.zero-width": "hidden zero-width character",
    "instr.credentials": "credential reference",
    "instr.squattable_domain": "squattable domain",
    "instr.base64_payload": "encoded command",
}


# --------------------------------------------------------------------------- #
#  Signing                                                                     #
# --------------------------------------------------------------------------- #
# Two integrity modes, and we are honest about the difference:
#   * passphrase mode (VETGATE_PASSPHRASE set): the HMAC key is derived with PBKDF2
#     and NEVER written to disk, so even an attacker running as you cannot re-sign a
#     doctored baseline without the passphrase. This is real tamper-resistance.
#   * stored-key mode (default): a random key at ~/.vetgate/key (0600). This detects
#     ACCIDENTAL edits and other-user tampering, but NOT a same-uid attacker, who can
#     read the key and re-sign. The report says which mode is in effect.
SALT_PATH = os.path.join(VETGATE_HOME, "salt")


def key_mode() -> str:
    return "passphrase" if os.environ.get("VETGATE_PASSPHRASE") else "stored-key"


def _ensure_salt() -> bytes:
    os.makedirs(VETGATE_HOME, exist_ok=True)
    if not os.path.exists(SALT_PATH):
        salt = os.urandom(16)
        with open(SALT_PATH, "wb") as fh:
            fh.write(salt)
        return salt
    with open(SALT_PATH, "rb") as fh:
        return fh.read()


def _ensure_key() -> bytes:
    passphrase = os.environ.get("VETGATE_PASSPHRASE")
    if passphrase:
        return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), _ensure_salt(), 200_000)
    os.makedirs(VETGATE_HOME, exist_ok=True)
    if not os.path.exists(KEY_PATH):
        key = os.urandom(32)
        fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.hex().encode())
        return key
    with open(KEY_PATH, "rb") as fh:
        return bytes.fromhex(fh.read().decode().strip())


def _sign(payload: bytes) -> str:
    return hmac.new(_ensure_key(), payload, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
#  Fact extraction                                                             #
# --------------------------------------------------------------------------- #
def _facts_for(rel: str, content: str) -> dict:
    """Semantic fingerprint of a file: which detectors fire and how often."""
    ids: Dict[str, int] = {}
    max_sev = 0
    for f in analyze_file(rel, content, ref="local-config"):
        ids[f.id] = ids.get(f.id, 0) + 1
        max_sev = max(max_sev, int(f.severity))
    return {"ids": ids, "max_sev": max_sev}


def _iter_files(roots: List[str]):
    for root in roots:
        root = os.path.expanduser(root)
        if os.path.isfile(root):
            yield root, root
        elif os.path.isdir(root):
            for dp, dn, fns in os.walk(root):
                dn[:] = [d for d in dn if d not in ("node_modules", "Cache", "CachedData", "logs")]
                for fn in fns:
                    yield os.path.join(dp, fn), root


def _snapshot(roots: List[str]) -> Dict[str, dict]:
    files: Dict[str, dict] = {}
    for full, _root in _iter_files(roots):
        try:
            st = os.stat(full)
            if st.st_size > MAX_BYTES or not stat.S_ISREG(st.st_mode):
                continue
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        entry = {
            "sha256": hashlib.sha256(content.encode("utf-8", "replace")).hexdigest(),
            "size": st.st_size,
            "mtime": st.st_mtime,
        }
        facts = _facts_for(full, content)
        if facts["ids"]:
            entry["facts"] = facts
        files[full] = entry
    return files


# --------------------------------------------------------------------------- #
#  Public API                                                                  #
# --------------------------------------------------------------------------- #
def create_baseline(roots: Optional[List[str]] = None) -> dict:
    roots = roots or DEFAULT_ROOTS
    existing = [r for r in roots if os.path.exists(os.path.expanduser(r))]
    baseline = {
        "version": 1,
        "created": time.time(),
        "roots": roots,
        "roots_present": existing,
        "files": _snapshot(roots),
    }
    payload = json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
    os.makedirs(VETGATE_HOME, exist_ok=True)
    with open(BASELINE_PATH, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(baseline, indent=2))
    with open(SIG_PATH, "w", encoding="utf-8") as fh:
        fh.write(_sign(payload))
    return baseline


def load_baseline() -> Optional[dict]:
    if not os.path.exists(BASELINE_PATH):
        return None
    with open(BASELINE_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _baseline_tampered(baseline: dict) -> bool:
    if not os.path.exists(SIG_PATH):
        return True
    payload = json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
    with open(SIG_PATH, "r", encoding="utf-8") as fh:
        stored = fh.read().strip()
    return not hmac.compare_digest(stored, _sign(payload))


def _attribution(path: str) -> str:
    base = os.path.basename(path).lower()
    if base in AGENT_MANAGED:
        return "likely the agent (agent-managed file) — heuristic"
    return "unknown: you or the agent? — heuristic, review"


def _sev_for_change(ids_delta: Dict[str, int]) -> Severity:
    # Planting a fetch-and-execute hook/script into your OWN config is the worst case.
    crit = {"claude.hook.rce", "npm.lifecycle.rce", "instr.pipe_to_shell",
            "instr.base64_payload", "watchdog.tampered"}
    hi = {"claude.hook", "vscode.task.folderopen", "devcontainer.lifecycle",
          "npm.lifecycle.suspicious", "env.exec_var", "instr.credentials",
          "mcp.env_secrets", "mcp.remote", "script.danger", "git.hook",
          "instr.imperative", "instr.hidden.unicode-tag", "instr.hidden.bidi-override"}
    if any(k in crit and v > 0 for k, v in ids_delta.items()):
        return Severity.CRITICAL
    if any(k in hi and v > 0 for k, v in ids_delta.items()):
        return Severity.HIGH
    if any(v > 0 for v in ids_delta.values()):
        return Severity.MEDIUM
    return Severity.LOW


def _describe(ids_delta: Dict[str, int]) -> str:
    bits = []
    for k, v in sorted(ids_delta.items()):
        if v > 0:
            name = _PHRASE.get(k, k)
            bits.append(f"+{v} {name}{'s' if v > 1 else ''}")
    return ", ".join(bits) if bits else "content changed"


def diff_against_baseline(roots: Optional[List[str]] = None) -> List[Finding]:
    baseline = load_baseline()
    if baseline is None:
        raise FileNotFoundError("no baseline — run `vetgate baseline` first")

    findings: List[Finding] = []
    if _baseline_tampered(baseline):
        extra = ("" if key_mode() == "passphrase" else
                 " (Note: in stored-key mode the key lives next to the baseline, so a "
                 "process running as you could also re-sign — set VETGATE_PASSPHRASE for "
                 "true tamper-resistance.)")
        findings.append(Finding(
            id="watchdog.tampered", title="vetgate baseline signature invalid",
            severity=Severity.CRITICAL, surface="watchdog", path=BASELINE_PATH,
            detail="The baseline does not match its HMAC signature — it was edited outside vetgate." + extra,
            trigger="would hide subsequent config changes from this watchdog",
            recommendation="Re-create the baseline on a known-good machine (`vetgate baseline`).",
            tags=["watchdog", "tamper"]))

    roots = roots or baseline.get("roots", DEFAULT_ROOTS)
    now = _snapshot(roots)
    old = baseline.get("files", {})
    old_keys, new_keys = set(old), set(now)

    for path in sorted(new_keys - old_keys):
        entry = now[path]
        facts = entry.get("facts", {"ids": {}})
        delta = facts["ids"]
        sev = _sev_for_change(delta) if delta else Severity.MEDIUM
        findings.append(Finding(
            id="watchdog.new_file", title=f"New agent-config file: {os.path.basename(path)}",
            severity=sev, surface="watchdog", path=path,
            detail=f"Appeared since baseline ({_describe(delta)}). Attribution: {_attribution(path)}.",
            evidence=_mtime(entry), trigger="loaded/executed by the agent or IDE per its type",
            recommendation="If you did not create this, treat it as a planted config.",
            tags=["watchdog", "new"]))

    for path in sorted(old_keys - new_keys):
        findings.append(Finding(
            id="watchdog.removed_file", title=f"Agent-config file removed: {os.path.basename(path)}",
            severity=Severity.LOW, surface="watchdog", path=path,
            detail="Present at baseline, now gone.", trigger="n/a",
            recommendation="Confirm the removal was intentional.", tags=["watchdog", "removed"]))

    for path in sorted(old_keys & new_keys):
        o, n = old[path], now[path]
        if o.get("sha256") == n.get("sha256"):
            continue
        o_ids = (o.get("facts") or {}).get("ids", {})
        n_ids = (n.get("facts") or {}).get("ids", {})
        delta = {k: n_ids.get(k, 0) - o_ids.get(k, 0)
                 for k in set(o_ids) | set(n_ids)}
        delta = {k: v for k, v in delta.items() if v > 0}
        sev = _sev_for_change(delta)
        findings.append(Finding(
            id="watchdog.modified", title=f"Agent-config changed: {os.path.basename(path)}",
            severity=sev, surface="watchdog", path=path,
            detail=f"{_describe(delta)}. Attribution: {_attribution(path)}.",
            evidence=_mtime(n),
            trigger="takes effect next time the agent/IDE reads this file",
            recommendation="Was this you? If not, revert and rotate any exposed secrets.",
            tags=["watchdog", "modified"]))
    return findings


def _mtime(entry: dict) -> str:
    try:
        return "changed " + time.strftime("%Y-%m-%d %H:%M", time.localtime(entry["mtime"]))
    except Exception:
        return ""
