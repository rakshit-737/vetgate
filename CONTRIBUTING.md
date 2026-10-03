# Contributing to vetgate

Thanks for helping make AI coding agents safer to run.

## The most useful contribution: harder test cases
The benchmark in `bench/corpus.py` is authored alongside the detectors, so a clean
sweep there only proves self-consistency. **The corpus wants adversarial cases** —
evasions vetgate currently misses, new agent/IDE conventions, real (sanitised) incident
patterns. Add a `Case(..., dangerous=True/False, category=...)`, run `python bench/run_bench.py`,
and if vetgate misses it, even better: open the PR with the failing case and we fix the detector.

Keep every fixture **inert** — placeholder commands pointing at `example.com`, never working
payloads.

## Dev setup
```bash
pip install -e ".[dev]"
pytest -q
python bench/run_bench.py
ruff check src
```

## Scope
vetgate is **defensive and local-first**: it inventories and monitors what *you* own or are
about to open. Detectors are deterministic; the optional LLM layer may only *explain* findings,
never be the sole thing that decides one exists. PRs that add offensive capability, require a
paid API for the core, or phone home will be declined.
