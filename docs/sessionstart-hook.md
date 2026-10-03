# Run vetgate as a Claude Code SessionStart hook

The most on-brand way to use vetgate: let it guard the very surface it audits. This
makes Claude Code run the **watchdog diff** every time a session starts, so you are
told immediately if your own agent config changed since your last trusted baseline —
"a new SessionStart hook appeared", "+3 imperative instructions in CLAUDE.md".

> vetgate's own SessionStart hook runs `vetgate watch` (read-only, offline). It does
> **not** fetch or execute anything — which is exactly the kind of hook vetgate flags
> as CRITICAL when it *does*.

## 1. Create your baseline once
```bash
vetgate baseline
```

## 2. Add the hook to `~/.claude/settings.json`
```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "vetgate watch --fail-on none" }
        ]
      }
    ]
  }
}
```

After you intentionally change your config, refresh the baseline with `vetgate baseline`
so the signed snapshot matches your new known-good state.

## Scan a repo before you open it in the agent
```bash
git clone <url> proj && vetgate scan proj --all-refs
# review the grade, THEN open it in Claude Code / Cursor
```
