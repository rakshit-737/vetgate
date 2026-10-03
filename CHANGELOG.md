# Changelog

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
- Benchmark: 26-case labelled corpus with a precision/recall harness (`bench/run_bench.py`).
