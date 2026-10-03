<div align="center">

# vetgate

### Catch what your AI coding agent silently trusts.

A local-first **watchdog for your own agent config** + an **all-branches sweep** for the repos you open — so a planted `SessionStart` hook or a hidden instruction can't run before you ever see it.

[![ci](https://github.com/rakshit-737/vetgate/actions/workflows/ci.yml/badge.svg)](https://github.com/rakshit-737/vetgate/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/vetgate.svg)](https://pypi.org/project/vetgate/)
[![Python](https://img.shields.io/pypi/pyversions/vetgate.svg)](https://pypi.org/project/vetgate/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

</div>

---

Your coding agent — Claude Code, Cursor, Copilot, Windsurf — will run whatever a workspace tells it to: a `SessionStart` hook, a `runOn: folderOpen` task, a devcontainer command, a line in `CLAUDE.md`. In 2026 that became the attack surface: the **keyv npm worm** planted `.claude/settings.json` and `.vscode/tasks.json` auto-run hooks so *opening* a repo re-ran its payload; **self-propagating instructions** quietly rewrote `CLAUDE.md` / `MEMORY.md`.

There are good scanners that check a repo's config **once, on the branch you have checked out**. `vetgate` does the two things they don't:

## 1. It watches *your own* machine — "was it you, or the agent?"

Static scanners tell you if a repo is safe to open. They go quiet the moment it's trusted and your agent is running — which is exactly when `~/.claude/settings.json` sprouts a new hook or `CLAUDE.md` gains three lines you didn't write. git never sees `~/.claude`.

```console
$ vetgate baseline          # signed snapshot of your own agent config, once
$ vetgate watch             # ...later, after an agent session

Workspace Trust: F   1 critical · 1 high
  [CRITICAL] watchdog  Agent-config changed: settings.json
             +1 fetch-and-execute hook. Attribution: likely the agent — heuristic.
             ↳ takes effect next time the agent/IDE reads this file
  [HIGH    ] watchdog  New agent-config file: CLAUDE.md
             +2 imperative instructions. Attribution: unknown — you or the agent? review.
```

Generic file-integrity monitors (AIDE, Tripwire, osquery) can diff those directories too — but none understand the *contents*: "a new SessionStart hook", "+2 imperative instructions", "a credential path appeared", and whether it was you or the agent. The baseline is **signed**; set `VETGATE_PASSPHRASE` and the key is derived, never written to disk, so it resists even a same-uid attacker re-signing a doctored baseline (otherwise it catches accidental and other-user edits — vetgate says which mode is active).

## 2. It sweeps *every branch*, not just the one you're on

A payload planted on a stale or non-default branch never touches your working tree — so a checked-out-tree scanner can't see it, yet it ships in the repo and fires the moment someone checks that branch out. (Secret scanners like gitleaks and trufflehog already sweep full history — for *secrets*. vetgate sweeps every ref for *agent auto-exec and instruction surfaces*, which they don't look at.)

```console
$ vetgate scan --all-refs ./acme-sdk

vetgate — ./acme-sdk
Workspace Trust: F   1C 3H 3M 2L
  [CRITICAL] claude-code      Claude Code hook fetches & executes code (HIDDEN ON BRANCH)  [staging] .claude/settings.json
             ↳ runs automatically when the Claude Code session starts
  [HIGH    ] instruction-file  Agent-directed imperative / injection phrasing  CLAUDE.md:3
  [HIGH    ] instruction-file  References to credential files / secret env vars  CLAUDE.md
  [HIGH    ] vscode           VS Code task runs on folder open  .vscode/tasks.json
  [MEDIUM  ] mcp              Remote MCP server 'notes'  .mcp.json
  ...
refs swept: 2/2
```

See it yourself in ten seconds — this builds a deliberately-unsafe repo (inert, example.com placeholders) and scans it:

```bash
uvx vetgate demo
```

## Quickstart

```bash
uvx vetgate scan --all-refs            # no install; scan the current repo across all refs
# or
pipx install vetgate                   # or: pip install vetgate
# before the PyPI release lands, install from source:
# pipx install git+https://github.com/rakshit-737/vetgate

vetgate scan .                         # pre-flight a repo before you open it in an agent
vetgate scan --all-refs --explain      # add branch sweep + plain-English explanations
vetgate baseline                       # snapshot your own ~/.claude, ~/.cursor, ...
vetgate watch                          # what changed since — you or the agent?
```

Core mode is **offline, deterministic, no API key.** It runs on a laptop in well under a second.

## How it compares

vetgate is new; the tools below are established and worth running. The point isn't stars, it's coverage — these two columns are the gap vetgate exists to fill:

| | all-refs sweep of **agent** surfaces | personal-config watchdog + attribution | one-shot repo preflight | license |
|---|:---:|:---:|:---:|---|
| **vetgate** | ✅ | ✅ (signed, "you or the agent?") | ✅ | Apache-2.0 |
| repo-forensics | ❌ (checkout only) | ⚠️ repo-scoped drift only | ✅ | Noncommercial |
| deepsafe-scan | ❌ | ❌ | ✅ | — |
| medusa | ❌ (one named branch) | ❌ | ✅ | — |
| gitleaks / trufflehog | ✅ but **secrets only** | ❌ | ❌ | permissive |
| AIDE / Tripwire / osquery (FIM) | ❌ | ⚠️ byte-diff, not agent-aware | ❌ | varies |

*Capabilities by category, observed Oct 2026 — not a slight on these tools; run them too (defense in depth). The columns are the gap vetgate fills: an all-refs sweep aimed specifically at agent auto-exec/instruction surfaces, and a watchdog that reads agent config **semantically** and attributes changes. Stars aren't the comparison; coverage is.*

## What it inventories

**Auto-execution surfaces** — Claude Code hooks (`SessionStart`/`PreToolUse`/…) & `enableAllProjectMcpServers`; `.mcp.json` (remote servers, `npx -y` auto-install, secrets handed to servers); VS Code `tasks.json` `runOn: folderOpen`; devcontainer lifecycle commands; `AGENTS.md` / `.github/copilot-instructions.md`; git hooks & `core.hooksPath`; npm/pip lifecycle scripts; direnv `.envrc`; and the quiet ones most tools miss — `LD_PRELOAD`, `DYLD_*`, `NODE_OPTIONS`, `BASH_ENV`, `PYTHONPATH`, `GIT_SSH_COMMAND`, `PATH`.

**Instruction-file threats** — hidden zero-width / bidi / **Unicode-tag-block** characters, homoglyphs, agent-directed imperatives ("ignore previous… without telling the user"), credential-path references, squattable placeholder domains (`third-party.com` class; RFC-2606 `example.com` is treated as safe), and base64 blobs that decode to commands.

Ordinary, legitimate patterns (a plain `postinstall`, a devcontainer `pip install`, a local MCP server) stay **low severity** — vetgate escalates to HIGH/CRITICAL only on genuinely dangerous content, so it doesn't cry wolf.

## Use it everywhere

**Pre-commit** — block auto-run surfaces & injected instructions before they land:
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/rakshit-737/vetgate
    rev: v0.1.0
    hooks: [{ id: vetgate }]
```

**GitHub Action** — scan every PR, across refs, with the report in the job summary:
```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }     # needed for the all-refs sweep
- uses: rakshit-737/vetgate@v0.1.0
  with: { fail-on: high }
```

**Claude Code SessionStart hook** — let vetgate guard the very surface it audits (it runs the read-only watchdog, the opposite of the hooks it flags). See [`docs/sessionstart-hook.md`](docs/sessionstart-hook.md).

## Does it actually work? (benchmark)

```
vetgate benchmark — 26 cases (14 dangerous / 12 benign)
  precision=1.00  recall=1.00  F1=1.00  accuracy=1.00
```

Run it yourself: `python bench/run_bench.py`. **Honest framing:** this corpus is authored alongside the detectors, so a clean sweep proves *self-consistency and zero false positives on common-legit configs*, not independent robustness. The benign half is deliberately full of the legitimate patterns naive scanners over-flag. The best contribution you can make is an **adversarial case that vetgate misses** — see [CONTRIBUTING](CONTRIBUTING.md).

## Known limitations

vetgate is a detection aid, not a guarantee. A clean report means "no check fired," not "safe." It does **not** yet catch: split-string / templated command reassembly, homoglyph domains outside its blocklist, encrypted or multi-stage payloads, or conventions it doesn't know about yet. Attribution in `watch` is a documented heuristic, not proof. Always pair it with least-privilege agent settings and a real sandbox for untrusted code.

## Design principles

- **Local-first & offline.** Core makes zero network calls; no account, no API key.
- **Deterministic core.** Rules and scoring decide every finding. The optional `--explain` layer only *rewords* findings the core already made — AI is never what decides something is a problem.
- **Defensive only.** vetgate inventories and monitors what you own or are about to open. It is not an attack tool.

## Background & roadmap

The incidents that motivated each check (public advisories): the [keyv npm worm planting agent/IDE hooks](https://snyk.io/blog/inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/), [Deadbugz MCP metadata poisoning](https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign), [weaponized placeholder domains in agent skills](https://thehackernews.com/2026/09/placeholder-third-partycom-referenced.html), and [self-propagating instructions in agent files](https://thehackernews.com/2026/08/ai-mind-viruses-can-spread-between.html). What's next is in [`docs/roadmap.md`](docs/roadmap.md) (MCP-server surface, real-time `watch --daemon`, SARIF output).

## License
[Apache-2.0](LICENSE) — permissive, use it anywhere. Contributions welcome under [CONTRIBUTING](CONTRIBUTING.md); report issues privately per [SECURITY](SECURITY.md).
