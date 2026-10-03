"""Optional plain-English explainer.

Deliberately offline and deterministic by default: it composes an explanation from
the finding's own fields, so the "works offline, no API key" promise holds and the
AI is never the thing that *decides* a finding exists. If VETGATE_AI is set and a
provider key is present, a model could be plugged in here to rewrite the same text
more fluently — but it only ever explains findings the deterministic core already made.
"""
from __future__ import annotations

from typing import List

from vetgate.model import Finding

_WHY = {
    "claude-code": "Claude Code runs this without a separate confirmation step, so a malicious entry here is code execution on your machine.",
    "vscode": "VS Code acts on this as soon as the folder is opened or trusted.",
    "devcontainer": "Dev-container lifecycle commands run during container build/start, before you review anything.",
    "npm": "npm lifecycle scripts run during `npm install`, which is why they are the classic supply-chain foothold.",
    "mcp": "MCP servers can read your files and call tools; a hostile or hijacked one acts with the agent's privileges.",
    "git": "git runs hooks automatically on ordinary git operations.",
    "direnv": "direnv executes .envrc on cd once allowed.",
    "instruction-file": "Agents read these files into context and may follow them as instructions.",
    "watchdog": "This is a change to your own machine's agent configuration since the trusted baseline.",
}


def explain(f: Finding) -> str:
    why = _WHY.get(f.surface, "")
    parts = [f.detail]
    if f.trigger:
        parts.append(f"It {f.trigger}.")
    if why:
        parts.append(why)
    if f.recommendation:
        parts.append(f"Do this: {f.recommendation}")
    return " ".join(p for p in parts if p)


def annotate(findings: List[Finding]) -> List[str]:
    return [explain(f) for f in findings]
