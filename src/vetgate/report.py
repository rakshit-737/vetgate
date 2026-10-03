"""Rendering: a screenshot-worthy terminal report, plus Markdown and JSON.

The letter grade and the "hidden on a branch you never checked out" callout are the
two things meant to end up in a screenshot, so they lead the terminal output.
"""
from __future__ import annotations

import json
import os
import pathlib
from typing import List

from vetgate import __version__
from vetgate.model import Finding, Grade, Severity

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    _RICH = True
except Exception:  # pragma: no cover
    _RICH = False

SEV_COLOR = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
GRADE_COLOR = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "bold white on red"}
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub code scanning buckets these: >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), not f.only_on_ref, f.surface, f.path))


def render_terminal(findings: List[Finding], grade: Grade, meta: dict, target: str) -> None:
    if not _RICH:
        _render_plain(findings, grade, meta, target)
        return
    con = Console()
    hidden = [f for f in findings if f.only_on_ref]

    head = Text()
    head.append("  vetgate  ", style="bold white on blue")
    head.append(f"  {target}\n", style="bold")
    head.append("Workspace Trust: ", style="")
    head.append(f" {grade.letter} ", style=GRADE_COLOR.get(grade.letter, "bold"))
    c = grade.counts
    head.append(f"   {c['CRITICAL']} critical · {c['HIGH']} high · {c['MEDIUM']} medium · "
                f"{c['LOW']} low   (risk score {grade.score})", style="dim")
    con.print(Panel(head, border_style=GRADE_COLOR.get(grade.letter, "blue")))

    if hidden:
        t = Text()
        t.append("⚑ ", style="bold red")
        t.append(f"{len(hidden)} finding(s) live on a ref you have NOT checked out — "
                 "invisible to a normal working-tree scan:\n", style="bold")
        for f in hidden[:6]:
            t.append(f"   • [{f.ref}] {f.title}  ({f.path})\n", style="red")
        con.print(Panel(t, title="hidden on another branch", border_style="red"))

    if not findings:
        con.print("[green]No execution or instruction surfaces flagged. Looks clean.[/green]")
        _meta_line(con, meta)
        return

    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("SEV", width=8)
    table.add_column("SURFACE", width=14)
    table.add_column("FINDING")
    table.add_column("WHERE", overflow="fold")
    for f in _sorted(findings):
        where = f.path + (":%d" % f.line if f.line else "")
        if f.ref and f.ref not in ("working-tree", "local-config"):
            where = f"[{f.ref}] " + where
        sev = Text(f.severity.label, style=SEV_COLOR[f.severity])
        title = f.title + (f"\n[dim]{f.trigger}[/dim]" if f.trigger else "")
        table.add_row(sev, f.surface, title, where)
    con.print(table)
    _meta_line(con, meta)


def _meta_line(con, meta: dict) -> None:
    if meta.get("refs_scanned"):
        msg = f"refs swept: {meta['refs_scanned']}/{meta['refs_total']}"
        if meta.get("truncated"):
            msg += f" — TRUNCATED at --max-refs; {meta['refs_total'] - meta['refs_scanned']} not scanned"
        con.print(f"[dim]{msg}[/dim]")
    if meta.get("error"):
        con.print(f"[dim]note: {meta['error']}[/dim]")


def _render_plain(findings, grade, meta, target):
    print(f"vetgate — {target}")
    print(f"Workspace Trust: {grade.letter}   "
          f"{grade.counts['CRITICAL']}C {grade.counts['HIGH']}H "
          f"{grade.counts['MEDIUM']}M {grade.counts['LOW']}L")
    for f in _sorted(findings):
        where = f.path + (f":{f.line}" if f.line else "")
        if f.ref not in ("working-tree", "local-config"):
            where = f"[{f.ref}] " + where
        flag = " (HIDDEN ON BRANCH)" if f.only_on_ref else ""
        print(f"  [{f.severity.label:8}] {f.surface:12} {f.title}{flag}  {where}")
        if f.trigger:
            print(f"             ↳ {f.trigger}")
    if meta.get("refs_scanned"):
        print(f"refs swept: {meta['refs_scanned']}/{meta['refs_total']}"
              + ("  (TRUNCATED)" if meta.get("truncated") else ""))


def build_json(findings: List[Finding], grade: Grade, meta: dict, target: str) -> str:
    return json.dumps({
        "target": target,
        "grade": grade.letter,
        "score": grade.score,
        "counts": grade.counts,
        "meta": meta,
        "findings": [f.to_dict() for f in _sorted(findings)],
    }, indent=2)


def _md_cell(text) -> str:
    return " ".join(str(text).splitlines()).replace("|", r"\|")


def build_markdown(findings: List[Finding], grade: Grade, meta: dict, target: str) -> str:
    lines = [f"# vetgate report — `{target}`", "",
             f"**Workspace Trust grade: {grade.letter}**  ",
             f"{grade.counts['CRITICAL']} critical · {grade.counts['HIGH']} high · "
             f"{grade.counts['MEDIUM']} medium · {grade.counts['LOW']} low "
             f"(risk score {grade.score})", ""]
    hidden = [f for f in findings if f.only_on_ref]
    if hidden:
        lines += ["## ⚑ Hidden on a non-checked-out ref", ""]
        for f in hidden:
            lines.append(f"- **[{f.ref}] {_md_cell(f.title)}** — `{_md_cell(f.path)}` — {_md_cell(f.detail)}")
        lines.append("")
    lines += ["## Findings", "",
              "| Severity | Surface | Finding | Where | Triggers |",
              "|---|---|---|---|---|"]
    for f in _sorted(findings):
        where = f.path + (f":{f.line}" if f.line else "")
        if f.ref not in ("working-tree", "local-config"):
            where = f"[{f.ref}] " + where
        lines.append(f"| {f.severity.label} | {_md_cell(f.surface)} | {_md_cell(f.title)} | "
                     f"`{_md_cell(where)}` | {_md_cell(f.trigger)} |")
    if meta.get("refs_scanned"):
        lines += ["", f"_refs swept: {meta['refs_scanned']}/{meta['refs_total']}"
                  + ("  (TRUNCATED at --max-refs)" if meta.get("truncated") else "") + "_"]
    return "\n".join(lines) + "\n"


def _sarif_location(f: Finding) -> dict:
    if os.path.isabs(f.path):
        artifact = {"uri": pathlib.Path(f.path).as_uri()}
    else:
        artifact = {"uri": f.path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"}
    physical = {"artifactLocation": artifact}
    if f.line:
        physical["region"] = {"startLine": f.line}
    return {"physicalLocation": physical}


def build_sarif(findings: List[Finding], grade: Grade, meta: dict, target: str) -> str:
    rules: dict = {}
    results = []
    for f in _sorted(findings):
        # _sorted is worst-first, so a rule takes the highest severity it is ever reported at
        rules.setdefault(f.id, {
            "id": f.id,
            "shortDescription": {"text": f.title},
            "help": {"text": f.recommendation or f.title},
            "properties": {"tags": ["security", f.surface],
                           "security-severity": SECURITY_SEVERITY[f.severity]},
        })
        text = f.title + (f" — {f.detail}" if f.detail else "")
        if f.trigger:
            text += f" (triggers: {f.trigger})"
        if f.only_on_ref:
            text = f"[hidden on ref '{f.ref}'] {text}"
        results.append({
            "ruleId": f.id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": text},
            "locations": [_sarif_location(f)],
            "properties": {"severity": f.severity.label, "surface": f.surface,
                           "ref": f.ref, "onlyOnRef": f.only_on_ref},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "vetgate",
                "version": __version__,
                "informationUri": "https://github.com/rakshit-737/vetgate",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": target, "grade": grade.letter, "score": grade.score,
                           "meta": meta},
        }],
    }, indent=2)
