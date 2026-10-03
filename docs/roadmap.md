# Roadmap

v0.1 ships the two wedges (personal-config watchdog, all-refs sweep) plus the
cross-convention pre-flight inventory on four surfaces (CLI, pre-commit, GitHub
Action, Claude Code SessionStart hook). What's next, roughly in order:

- **MCP server surface** — expose `vetgate_scan` / `vetgate_watch` as MCP tools so an
  agent can vet a repo or its own config on demand. (Deliberately not shipped half-working
  in v0.1.)
- **`watch --daemon`** — real-time file-integrity monitoring (inotify / FSEvents) instead
  of on-demand diffs, so a planted hook is caught the moment it lands.
- **Better attribution** — correlate config changes with agent activity windows / editor
  process ownership to sharpen the "you or the agent?" verdict beyond today's heuristic.
- **Richer instruction analysis** — split-string and templated-command reassembly,
  broader TR39 confusable coverage, optional live RDAP domain-age enrichment.
- **`--sarif` output** for GitHub code scanning; signed JSON attestations of a clean scan.
- **More conventions** as the ecosystem invents them (new agent rule files, registries).

Want one of these sooner? Open an issue — or better, a failing `bench/corpus.py` case.
