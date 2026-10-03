"""Top-level orchestration: scan the working tree and (optionally) every git ref."""
from __future__ import annotations

from typing import List, Tuple

from vetgate.model import Finding
from vetgate.refs import sweep_refs
from vetgate.surfaces import scan_tree


def scan_workspace(path: str, all_refs: bool = False,
                   max_refs: int = 60) -> Tuple[List[Finding], dict]:
    findings: List[Finding] = list(scan_tree(path))
    meta: dict = {}
    if all_refs:
        ref_findings, meta = sweep_refs(path, max_refs=max_refs)
        findings.extend(ref_findings)
    return findings, meta
