"""Instruction-file threat analysis.

Agent-facing text files (CLAUDE.md, AGENTS.md, .cursorrules, MCP docs, READMEs the
agent is told to follow) are a first-class execution surface: whatever they say, a
trusting agent may do. This module turns one such file's *content* into findings.
"""
from __future__ import annotations

import base64
import binascii
from typing import List

from vetgate import patterns as P
from vetgate.model import Finding, Severity


def _sev(name: str) -> Severity:
    return Severity.from_str(name)


def analyze_text(text: str, path: str, surface: str = "instruction-file",
                 ref: str = "working-tree") -> List[Finding]:
    findings: List[Finding] = []

    # 1. Hidden / deceptive unicode -------------------------------------------
    hidden = P.scan_hidden_unicode(text)
    if hidden:
        by_reason: dict = {}
        for cp, idx, reason in hidden:
            by_reason.setdefault(reason, []).append((cp, idx))
        for reason, items in by_reason.items():
            cp0, idx0 = items[0]
            sev = Severity.HIGH if reason in ("bidi-override", "unicode-tag") else Severity.MEDIUM
            findings.append(Finding(
                id=f"instr.hidden.{reason}",
                title=f"Hidden unicode ({reason}) in agent-facing file",
                severity=sev,
                surface=surface, path=path, ref=ref,
                line=P.line_of(text, idx0),
                detail=f"{len(items)} invisible/{reason} character(s) that render as "
                       f"nothing but can carry instructions a human reviewer will not see.",
                evidence="first at U+%04X (line %d)" % (cp0, P.line_of(text, idx0)),
                trigger="read verbatim by the agent when this file is auto-loaded",
                recommendation="Strip non-printing characters; no legitimate instruction file needs them.",
                tags=["unicode", reason],
            ))

    # 2. Pipe-to-shell one-liners ---------------------------------------------
    for m in P.PIPE_TO_SHELL.finditer(text):
        findings.append(Finding(
            id="instr.pipe_to_shell",
            title="Download-and-execute one-liner in agent-facing file",
            severity=Severity.HIGH,
            surface=surface, path=path, ref=ref,
            line=P.line_of(text, m.start()),
            detail="Instruction tells the agent to pipe downloaded content straight into a shell/interpreter.",
            evidence=_clip(m.group(0)),
            trigger="executed if the agent follows the instruction",
            recommendation="Never let an agent run `curl … | sh`. Pin and review scripts instead.",
            tags=["rce", "pipe-to-shell"],
        ))

    # 3. Agent-directed imperatives -------------------------------------------
    for rx, sev_name in P.IMPERATIVE_PATTERNS:
        for m in rx.finditer(text):
            findings.append(Finding(
                id="instr.imperative",
                title="Agent-directed imperative / injection phrasing",
                severity=_sev(sev_name),
                surface=surface, path=path, ref=ref,
                line=P.line_of(text, m.start()),
                detail="Language that tries to steer the agent's behaviour "
                       "(override instructions, act without telling the user, auto-run, exfiltrate).",
                evidence=_clip(m.group(0)),
                trigger="interpreted as a command when the agent reads this file",
                recommendation="Treat as untrusted. Agent instruction files should describe the repo, not command the agent.",
                tags=["prompt-injection"],
            ))

    # 4. Credential references -------------------------------------------------
    creds = P.find_credential_refs(text)
    if creds:
        findings.append(Finding(
            id="instr.credentials",
            title="References to credential files / secret env vars",
            severity=Severity.HIGH,
            surface=surface, path=path, ref=ref,
            detail="Mentions secret material (" + ", ".join(sorted(set(creds))[:6]) + ") — "
                   "a classic exfiltration target when embedded in agent instructions.",
            evidence=", ".join(sorted(set(creds))[:6]),
            trigger="acted on if the agent follows the surrounding instruction",
            recommendation="Verify why an instruction file names secret paths; remove if unexpected.",
            tags=["secrets"],
        ))

    # 5. Squattable / placeholder domains -------------------------------------
    doms = P.find_squattable_domains(text)
    if doms:
        findings.append(Finding(
            id="instr.squattable_domain",
            title="Squattable placeholder domain referenced",
            severity=Severity.MEDIUM,
            surface=surface, path=path, ref=ref,
            detail="Non-reserved placeholder domain(s) (" + ", ".join(doms[:5]) + ") an attacker can "
                   "register to hijack agents that follow the docs literally.",
            evidence=", ".join(doms[:5]),
            trigger="contacted if the agent resolves/visits the URL",
            recommendation="Use RFC-2606 reserved names (example.com) or a domain you control.",
            tags=["domain", "slopsquat"],
        ))

    # 6. Confusable homoglyphs -------------------------------------------------
    conf = P.has_confusables(text)
    if conf:
        findings.append(Finding(
            id="instr.homoglyph",
            title="Homoglyph / confusable characters present",
            severity=Severity.MEDIUM,
            surface=surface, path=path, ref=ref,
            detail="Non-ASCII look-alike letters (" + " ".join(conf[:8]) + ") that can disguise a "
                   "command or domain as a trusted one.",
            evidence=" ".join(conf[:8]),
            trigger="misread by a human reviewer; may resolve to attacker infrastructure",
            recommendation="Normalise to ASCII; investigate why look-alikes are present.",
            tags=["unicode", "homoglyph"],
        ))

    # 7. Base64 blobs that decode to commands ---------------------------------
    for m in P.BASE64_BLOB.finditer(text):
        blob = m.group(0)
        decoded = _try_b64(blob)
        if decoded and (P.PIPE_TO_SHELL.search(decoded) or any(
                rx.search(decoded) for rx, _ in P.IMPERATIVE_PATTERNS)):
            findings.append(Finding(
                id="instr.base64_payload",
                title="Base64 blob that decodes to a command",
                severity=Severity.HIGH,
                surface=surface, path=path, ref=ref,
                line=P.line_of(text, m.start()),
                detail="Obfuscated content decodes to shell/agent instructions.",
                evidence=_clip(decoded),
                trigger="executed if the agent is told to decode and run it",
                recommendation="Never auto-decode untrusted blobs; inspect before use.",
                tags=["obfuscation", "rce"],
            ))
    return findings


def _clip(s: str, n: int = 120) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _try_b64(blob: str):
    try:
        raw = base64.b64decode(blob, validate=True)
        return raw.decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None
