"""vetgate command-line interface.

    vetgate scan [PATH]       inventory everything an agent would auto-run/trust here
    vetgate scan --all-refs   also sweep every branch/tag (finds payloads off the checkout)
    vetgate baseline          snapshot your own ~/.claude, ~/.cursor ... (signed)
    vetgate watch             diff against the baseline: "what changed — you or the agent?"
    vetgate demo              build a deliberately unsafe repo and scan it (see the wow)
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from typing import List, Optional

from vetgate import __version__
from vetgate import report as R
from vetgate.engine import scan_workspace
from vetgate.model import Finding, Severity, grade_findings

_FAIL_LEVELS = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW, "none": None}


def _emit(findings: List[Finding], meta: dict, target: str, args) -> None:
    grade = grade_findings(findings)
    if getattr(args, "json", False):
        print(R.build_json(findings, grade, meta, target))
    else:
        R.render_terminal(findings, grade, meta, target)
    if getattr(args, "md", None):
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(R.build_markdown(findings, grade, meta, target))
        if not args.json:
            print(f"\nMarkdown report written to {args.md}")
    if getattr(args, "sarif", None):
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(R.build_sarif(findings, grade, meta, target))
        if not args.json:
            print(f"SARIF report written to {args.sarif}")
    if getattr(args, "explain", False) and findings and not args.json:
        from vetgate.explain import explain
        print("\nExplanations:")
        for f in sorted(findings, key=lambda x: -int(x.severity)):
            print(f"  • {f.title}\n      {explain(f)}")


def _exit_code(findings: List[Finding], fail_on: Optional[Severity]) -> int:
    if fail_on is None:
        return 0
    return 1 if any(int(f.severity) >= int(fail_on) for f in findings) else 0


def cmd_scan(args) -> int:
    path = os.path.abspath(args.path)
    if not os.path.isdir(path):
        print(f"vetgate: not a directory: {path}", file=sys.stderr)
        return 2
    findings, meta = scan_workspace(path, all_refs=args.all_refs, max_refs=args.max_refs)
    if args.min_severity:
        floor = Severity.from_str(args.min_severity)
        findings = [f for f in findings if int(f.severity) >= int(floor)]
    _emit(findings, meta, path, args)
    return _exit_code(findings, _FAIL_LEVELS[args.fail_on])


def cmd_baseline(args) -> int:
    from vetgate.watch import BASELINE_PATH, create_baseline, key_mode, load_baseline
    roots = args.roots or None
    if load_baseline() is not None:
        print("vetgate: note — overwriting the existing baseline (its prior state is replaced).")
    bl = create_baseline(roots)
    present = bl.get("roots_present", [])
    n = len(bl.get("files", {}))
    mode = key_mode()
    print(f"vetgate: signed baseline written to {BASELINE_PATH}  [integrity mode: {mode}]")
    if mode == "stored-key":
        print("  tip: set VETGATE_PASSPHRASE to resist a same-uid attacker, not just accidental edits.")
    print(f"  tracked {n} config file(s) across {len(present)} present root(s):")
    for r in present:
        print(f"    - {r}")
    if not present:
        print("  (no default roots found on this machine; pass --roots to point at your config)")
    return 0


def cmd_watch(args) -> int:
    from vetgate.watch import diff_against_baseline
    try:
        findings = diff_against_baseline(args.roots or None)
    except FileNotFoundError as e:
        print(f"vetgate: {e}", file=sys.stderr)
        return 2
    meta = {}
    target = "your agent config (since baseline)"
    _emit(findings, meta, target, args)
    if not findings and not args.json:
        print("No changes to your agent config since the baseline.")
    return _exit_code(findings, _FAIL_LEVELS[args.fail_on])


def cmd_demo(args) -> int:
    from vetgate.demo import build_vulnerable_repo
    dest = args.path or os.path.join(tempfile.gettempdir(), "vetgate-demo")
    if os.path.exists(dest) and not args.path:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
    build_vulnerable_repo(dest)
    print(f"Built a deliberately-unsafe demo repo at: {dest}")
    print("Running:  vetgate scan --all-refs\n")
    findings, meta = scan_workspace(dest, all_refs=True, max_refs=60)
    args.json = False
    args.md = None
    args.explain = False
    _emit(findings, meta, dest, args)
    print("\nNote how the CRITICAL hook is tagged 'hidden on another branch' — a "
          "working-tree scanner never checks that ref out, so it would miss it.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vetgate",
                                description="Catch what your AI coding agent silently trusts.")
    p.add_argument("--version", action="version", version=f"vetgate {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def add_common(sp):
        sp.add_argument("--json", action="store_true", help="machine-readable output")
        sp.add_argument("--md", metavar="FILE", help="also write a Markdown report")
        sp.add_argument("--sarif", metavar="FILE",
                        help="also write a SARIF 2.1.0 report (GitHub code scanning)")
        sp.add_argument("--fail-on", choices=list(_FAIL_LEVELS), default="high",
                        help="exit non-zero if a finding at/above this severity exists (default: high)")

    sp = sub.add_parser("scan", help="inventory auto-run/instruction surfaces in a workspace")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("--all-refs", action="store_true",
                    help="also sweep every branch/tag/ref, not just the checkout")
    sp.add_argument("--max-refs", type=int, default=60)
    sp.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"])
    sp.add_argument("--explain", action="store_true", help="print plain-English explanations")
    add_common(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("baseline", help="snapshot your own agent config (signed)")
    sp.add_argument("--roots", nargs="*", help="override the config roots to track")
    sp.set_defaults(func=cmd_baseline)

    sp = sub.add_parser("watch", help="diff your agent config against the baseline")
    sp.add_argument("--roots", nargs="*")
    sp.add_argument("--explain", action="store_true")
    add_common(sp)
    sp.set_defaults(func=cmd_watch)

    sp = sub.add_parser("demo", help="build and scan a deliberately-unsafe demo repo")
    sp.add_argument("path", nargs="?", default=None)
    sp.set_defaults(func=cmd_demo)
    return p


def _utf8_stdio() -> None:
    # Windows pipes/redirects default to the ANSI code page, which can't encode the report glyphs.
    for stream in (sys.stdout, sys.stderr):
        enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "")
        if enc != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: Optional[List[str]] = None) -> int:
    _utf8_stdio()
    args = build_parser().parse_args(argv)
    if not getattr(args, "cmd", None):
        build_parser().print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
