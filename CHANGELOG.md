# Changelog

## Unreleased
### Added
- `--sarif FILE` on `scan` and `watch`: SARIF 2.1.0 output for GitHub code scanning, with
  per-rule `security-severity` so findings land in GitHub's critical/high/medium/low buckets
  and hidden-on-another-ref findings are labelled in the message.

### Fixed
- Windows: `vetgate demo` and any scan with findings crashed with `UnicodeEncodeError` when
  stdout was piped or redirected (cp1252). The CLI and benchmark runner now write UTF-8.
- Windows: the hidden-branch test was always skipped because git detection shelled out to
  `/dev/null`; it now uses `shutil.which`.

## 0.1.0 — first public release
- **Personal-config watchdog** (`vetgate baseline` / `vetgate watch`): signed baseline of
  your own `~/.claude`, `~/.cursor`, `~/.vscode`, `~/.codex`, user LaunchAgents / systemd
  units and agent instruction files; semantic diff with "was it you or the agent?" attribution
  and HMAC tamper detection.
- **All-refs sweep** (`vetgate scan --all-refs`): inventories auto-run/instruction surfaces on
  every branch, tag and ref, flagging payloads that are absent from the working tree.
- Cross-convention pre-flight inventory: Claude Code hooks + `.mcp.json`, Cursor/Windsurf rules,
  VS Code `tasks.json` (`runOn: folderOpen`), devcontainer lifecycle, `AGENTS.md`,
  Copilot instructions, git hooks / `core.hooksPath`, npm/pip lifecycle scripts, direnv,
  plus code-exec env vars (`LD_PRELOAD`, `NODE_OPTIONS`, `BASH_ENV`, …).
- Instruction-file threat analysis: hidden/zero-width/bidi/tag-block unicode, homoglyphs,
  agent-directed imperatives, credential paths, squattable placeholder domains, base64 payloads.
- Deterministic A–F Workspace Trust grade; optional offline `--explain`.
- Surfaces: CLI, pre-commit hook, GitHub Action, Claude Code SessionStart hook.
- Benchmark: 34-case labelled corpus with a precision/recall harness (`bench/run_bench.py`).
