"""Shared detection primitives: hidden-unicode scanning, dangerous env vars,
credential paths, squattable domains, agent-directed imperatives and obfuscation.

Kept deterministic and dependency-free on purpose — the whole point of vetgate is
that the core verdicts don't need a model or a network.
"""
from __future__ import annotations

import re
import unicodedata
from typing import List, Tuple

# --- Hidden / deceptive unicode -------------------------------------------------
# Zero-width and format characters that render as nothing but can hide text, split
# tokens, or smuggle instructions past a human reviewing a diff.
ZERO_WIDTH = {
    0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0xFEFF, 0x00AD, 0x061C, 0x180E,
}
# Bidirectional overrides — the "Trojan Source" class (CVE-2021-42574).
BIDI = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
# Unicode TAG block: invisible, increasingly used to conceal instructions inside
# MCP tool metadata and to exploit the approval-view fidelity gap.
TAG_BLOCK = range(0xE0000, 0xE0080)
# Variation selectors: runs of them (and any supplementary one) can encode hidden bytes.
VS_BASIC = range(0xFE00, 0xFE10)
VS_SUPPLEMENT = range(0xE0100, 0xE01F0)
ZWJ = 0x200D


def _is_emoji(cp: int) -> bool:
    return cp >= 0x1F000 or 0x2600 <= cp <= 0x27BF or cp in VS_BASIC or 0x2190 <= cp <= 0x2BFF


def scan_hidden_unicode(text: str) -> List[Tuple[int, int, str]]:
    """Return (codepoint, char_index, reason) for every suspicious hidden char."""
    hits: List[Tuple[int, int, str]] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp in BIDI:
            hits.append((cp, i, "bidi-override"))
        elif cp in TAG_BLOCK:
            hits.append((cp, i, "unicode-tag"))
        elif cp in VS_SUPPLEMENT or (cp in VS_BASIC and i > 0 and ord(text[i - 1]) in VS_BASIC):
            hits.append((cp, i, "variation-selector"))
        elif cp == 0xFEFF and i == 0:
            continue
        elif cp == ZWJ and 0 < i < len(text) - 1 and _is_emoji(ord(text[i - 1])) and _is_emoji(ord(text[i + 1])):
            continue
        elif cp in ZERO_WIDTH:
            hits.append((cp, i, "zero-width"))
        elif cp not in (0x09, 0x0A, 0x0D) and unicodedata.category(ch) in ("Cc", "Cf"):
            hits.append((cp, i, "control-char"))
    return hits


# A small, high-signal slice of confusable (TR39) characters used to spoof ASCII in
# commands and domains. Not exhaustive — enough to catch the common homoglyph tricks.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "ο": "o",
    "ρ": "p", "ɑ": "a", "һ": "h", "ԛ": "q", "ԝ": "w", "ｅ": "e", "０": "0",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
}


_TOKEN_RX = re.compile(r"\S+")


def has_confusables(text: str) -> List[str]:
    """Only flag MIXED-SCRIPT tokens (an ASCII letter next to a look-alike) — the real
    spoofing signal. Pure Greek/Cyrillic/math prose is left alone to avoid false alarms.
    """
    out = set()
    for m in _TOKEN_RX.finditer(text):
        tok = m.group(0)
        conf = [c for c in tok if c in CONFUSABLES]
        if conf and any(("a" <= c <= "z") or ("A" <= c <= "Z") for c in tok):
            out.update(conf)
    return sorted(out)


# --- Dangerous environment variables -------------------------------------------
# Setting any of these in an auto-loaded file turns "open the folder" into "run my
# code": they inject code into shells, Python, Node or the dynamic linker.
EXEC_ENV_VARS = {
    "BASH_ENV", "ENV", "PROMPT_COMMAND", "PS0", "PS1",
    "PYTHONSTARTUP", "PYTHONPATH", "PYTHONBREAKPOINT",
    "NODE_OPTIONS", "NODE_REPL_EXTERNAL_MODULE",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
    "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_PAGER",
    "PERL5OPT", "RUBYOPT", "PATH",
}

_ENV_ASSIGN = re.compile(
    r"(?:^|[\s;&|])(?:(?P<ci>(?i:set)\s+|\$(?i:env):)|export\s+|setenv\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=",
    re.MULTILINE,
)


def find_exec_env_assignments(text: str) -> List[Tuple[str, int]]:
    """Return (VARNAME, char_offset) for assignments to code-exec env vars."""
    hits = []
    for m in _ENV_ASSIGN.finditer(text):
        # cmd `set` and PowerShell `$env:` names are case-insensitive; POSIX ones are not.
        name = m.group("name").upper() if m.group("ci") else m.group("name")
        if name in EXEC_ENV_VARS:
            hits.append((name, m.start("name")))
    return hits


# --- Credentials & secrets ------------------------------------------------------
CREDENTIAL_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"~?/?\.aws/credentials", r"~?/?\.ssh/(?:id_[a-z0-9]+|authorized_keys)",
        r"~?/?\.config/gh/hosts\.yml", r"~?/?\.npmrc", r"~?/?\.pypirc",
        r"~?/?\.netrc", r"~?/?\.docker/config\.json", r"~?/?\.kube/config",
        r"\bGITHUB_TOKEN\b", r"\bGH_TOKEN\b", r"\bAWS_SECRET_ACCESS_KEY\b",
        r"\bAWS_ACCESS_KEY_ID\b", r"\bANTHROPIC_API_KEY\b", r"\bOPENAI_API_KEY\b",
        r"\bNPM_TOKEN\b", r"\bHF_TOKEN\b", r"\bSLACK_TOKEN\b",
        r"process\.env\.[A-Z_]*(?:TOKEN|KEY|SECRET)[A-Z_]*",
    ]
]


def find_credential_refs(text: str) -> List[str]:
    out = []
    for rx in CREDENTIAL_PATTERNS:
        for m in rx.finditer(text):
            out.append(m.group(0))
    return out


# --- Squattable / placeholder domains ------------------------------------------
# RFC 2606 / 6761 reserved names are SAFE and never flagged.
RESERVED_SAFE = {
    "example.com", "example.org", "example.net", "example.edu",
    "localhost", "invalid", "test", "local",
}
# Non-reserved placeholders that real projects leave in docs and that attackers
# have registered to hijack agents that follow instructions literally.
SQUATTABLE_PLACEHOLDERS = {
    "third-party.com", "yoursite.com", "your-domain.com", "your-site.com",
    "mysite.com", "mydomain.com", "website.com", "domain.com", "company.com",
    "yourcompany.com", "acme.com", "foobar.com", "changeme.com", "placeholder.com",
    "api.example", "yourserver.com", "yourapi.com",
}

_DOMAIN_RX = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]{1,63})+)\b", re.I)


def find_squattable_domains(text: str) -> List[str]:
    out = []
    for m in _DOMAIN_RX.finditer(text):
        d = m.group(1).lower().rstrip(".")
        if d in RESERVED_SAFE:
            continue
        if any(d == p or d.endswith("." + p) for p in SQUATTABLE_PLACEHOLDERS):
            out.append(d)
    return sorted(set(out))


# --- Agent-directed imperatives & shell obfuscation ----------------------------
# (regex, weight-as-severity-name). These describe text aimed at steering an agent.
IMPERATIVE_PATTERNS = [
    (re.compile(r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?)", re.I), "HIGH"),
    (re.compile(r"disregard\s+(?:all\s+)?(?:the\s+)?(?:prior|previous|above|system|developer)\s+(?:instructions?|prompts?|messages?)", re.I), "HIGH"),
    (re.compile(r"do\s+not\s+(?:tell|inform|mention\s+to|notify|alert|warn)\s+the\s+(?:user|operator|human|developer)", re.I), "HIGH"),
    (re.compile(r"\b(?:quietly|secretly|silently|covertly|discreetly)\s+\w+", re.I), "MEDIUM"),
    (re.compile(r"without\s+(?:asking|telling|informing|notifying|confirmation|the\s+user)", re.I), "MEDIUM"),
    (re.compile(r"\b(?:exfiltrat|leak|upload|send|email|post|share|transmit|curl|wget)\w*\b.{0,50}\b(?:cred|secret|token|key|password|\.ssh|\.aws|\.env|\benv\b|config|contents?|file|data)\b", re.I), "HIGH"),
    (re.compile(r"\byou\s+must\s+(?:always\s+)?(?:run|execute|install|download|curl|wget)\b", re.I), "MEDIUM"),
    (re.compile(r"\b(?:always|automatically)\s+(?:run|execute|approve|allow)\b", re.I), "MEDIUM"),
    (re.compile(r"\bbase64\s+(?:-d|--decode)\b", re.I), "MEDIUM"),
    (re.compile(r"\beval\s*\(", re.I), "MEDIUM"),
    (re.compile(r"\brm\s+-rf\s+[~/]", re.I), "HIGH"),
]

PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest|fetch)\b[^\n|]{0,160}\|\s*"
    r"(?:sudo\s+)?(?:sh|bash|zsh|dash|python[0-9.]*|node|pwsh|powershell|ruby|perl)\b",
    re.I,
)

BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/])")

# `… | base64 -d | sh` style decode-and-run (no curl/wget prefix, so PIPE_TO_SHELL misses it)
BASE64_DECODE_EXEC = re.compile(
    r"base64\s+(?:-d|--decode|-D)\b[^\n|]{0,120}\|\s*(?:sudo\s+)?"
    r"(?:sh|bash|zsh|dash|python[0-9.]*|node|perl|ruby)\b", re.I)

RAW_FETCH = re.compile(r"\b(?:curl|wget|iwr|invoke-webrequest)\b", re.I)
INLINE_EVAL = re.compile(r"\b(?:node\s+-e|python[0-9.]*\s+-c|ruby\s+-e|perl\s+-e|eval)\b", re.I)


def _b64_decodes_to_danger(cmd: str) -> bool:
    """True only if a base64 blob in the string DECODES to a fetch/pipe/eval command.

    This is what stops ordinary 40+ char tokens — git SHAs, `sha512-…` integrity hashes,
    JWTs, data: URIs — from being misread as dangerous (the P0 false-positive).
    """
    import base64 as _b64
    import binascii as _bin
    for m in BASE64_BLOB.finditer(cmd):
        try:
            dec = _b64.b64decode(m.group(0), validate=True).decode("utf-8", "replace")
        except (_bin.Error, ValueError):
            continue
        if PIPE_TO_SHELL.search(dec) or RAW_FETCH.search(dec) or INLINE_EVAL.search(dec):
            return True
    return False


def command_danger(cmd: str):
    """Classify how dangerous a command string is, or None if it looks ordinary.

    Ordinary lifecycle commands (`tsc`, `node-gyp rebuild`, `pip install -r …`), and
    commands that merely CONTAIN a long token like a commit SHA or integrity hash, stay
    None — only fetch-pipe-execute, decode-execute, secret/exec-env access, or a bare
    network/eval call escalate. Returns "CRITICAL" / "HIGH" / None.
    """
    if PIPE_TO_SHELL.search(cmd) or BASE64_DECODE_EXEC.search(cmd) or _b64_decodes_to_danger(cmd):
        return "CRITICAL"
    if (find_credential_refs(cmd) or find_exec_env_assignments(cmd)
            or RAW_FETCH.search(cmd) or INLINE_EVAL.search(cmd)):
        return "HIGH"
    return None


# Does a hook command run *arbitrary / opaque* code (a repo-local script, an
# interpreter on a file, or shell operators) vs a known-benign dev tool? An auto-run
# hook that only invokes prettier/eslint/pytest is routine; one that runs `./setup.sh`
# or `python .ci/boot.py` automatically is the keyv-worm pattern.
_SCRIPT_EXEC = re.compile(
    r"\b(?:bash|sh|zsh|dash|python[0-9.]*|node|deno|bun|ruby|perl|pwsh|powershell)\b\s+\S+\.(?:sh|py|js|mjs|cjs|ts|rb|pl|ps1)\b"
    r"|\b(?:bash|sh|zsh|dash|python[0-9.]*|node|ruby|perl)\b\s+-\S"
    r"|(?:^|\s)\.\.?/\S+",
    re.I)
_SHELL_OP = re.compile(r";|&&|\|\||\$\(|`|\|")
KNOWN_SAFE_TOOLS = {
    "prettier", "eslint", "ruff", "black", "isort", "mypy", "pytest", "tsc", "biome",
    "gofmt", "go", "cargo", "rustfmt", "npm", "pnpm", "yarn", "clang-format", "dotnet",
    "make", "just", "pre-commit", "git",
}


def hook_runs_arbitrary(cmd: str) -> bool:
    c = cmd.strip()
    if _SHELL_OP.search(c) or _SCRIPT_EXEC.search(c):
        return True
    first = (c.split() or [""])[0].rsplit("/", 1)[-1]
    return first not in KNOWN_SAFE_TOOLS and bool(first)


def line_of(text: str, offset: int) -> int:
    """1-based line number for a character offset."""
    return text.count("\n", 0, offset) + 1
