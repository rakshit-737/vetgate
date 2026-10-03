"""Run vetgate over the labelled corpus and report precision / recall / F1.

    python bench/run_bench.py            # pretty table
    python bench/run_bench.py --md FILE  # also write a Markdown results file

Detection task: does the workspace contain a HIGH+ auto-exec / injection threat?
Runs with --all-refs so the hidden-on-a-branch case is in scope.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

from vetgate.engine import scan_workspace
from vetgate.model import Severity

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corpus import generate  # noqa: E402


def predict_dangerous(path: str) -> bool:
    findings, _ = scan_workspace(path, all_refs=True, max_refs=60)
    return any(int(f.severity) >= int(Severity.HIGH) for f in findings)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--md")
    args = ap.parse_args()
    # Windows pipes default to the ANSI code page, which can't encode the ✓/✗ outcome marks.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    base = tempfile.mkdtemp(prefix="vetgate-bench-")
    cases = generate(base)
    live = [c for c in cases if not c.skipped]
    skipped = [c for c in cases if c.skipped]

    tp = fp = tn = fn = 0
    rows = []
    for c in live:
        pred = predict_dangerous(c.path)
        if c.dangerous and pred:
            tp += 1; outcome = "TP ✓"
        elif c.dangerous and not pred:
            fn += 1; outcome = "FN ✗ (missed)"
        elif not c.dangerous and pred:
            fp += 1; outcome = "FP ✗ (false alarm)"
        else:
            tn += 1; outcome = "TN ✓"
        rows.append((c.name, c.category, "danger" if c.dangerous else "benign",
                     "HIGH+" if pred else "clean", outcome))

    prec = tp / (tp + fp) if (tp + fp) else 1.0
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / len(live) if live else 0.0

    print(f"\nvetgate benchmark — {len(live)} cases "
          f"({sum(c.dangerous for c in live)} dangerous / {sum(not c.dangerous for c in live)} benign)")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"  precision={prec:.3f}  recall={rec:.3f}  F1={f1:.3f}  accuracy={acc:.3f}")
    if skipped:
        print(f"  skipped (git unavailable): {', '.join(c.name for c in skipped)}")
    print()
    for name, cat, lbl, pred, outcome in rows:
        print(f"  {outcome:20} {name:26} [{cat}]  truth={lbl:6} pred={pred}")

    if args.md:
        lines = ["# vetgate benchmark results", "",
                 f"- Cases: **{len(live)}** ({sum(c.dangerous for c in live)} dangerous, "
                 f"{sum(not c.dangerous for c in live)} benign)",
                 f"- **Precision {prec:.2f} · Recall {rec:.2f} · F1 {f1:.2f} · Accuracy {acc:.2f}**",
                 f"- Confusion: TP={tp} FP={fp} TN={tn} FN={fn}", ""]
        if skipped:
            lines += [f"> skipped where git was unavailable: {', '.join(c.name for c in skipped)}", ""]
        lines += ["| Case | Category | Truth | Predicted | Outcome |", "|---|---|---|---|---|"]
        for name, cat, lbl, pred, outcome in rows:
            lines.append(f"| {name} | {cat} | {lbl} | {pred} | {outcome} |")
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"\nWrote {args.md}")

    return 1 if (fp or fn) else 0


if __name__ == "__main__":
    raise SystemExit(main())
