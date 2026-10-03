"""Core data types shared across vetgate: severities, findings and the trust grade."""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Optional


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.strip().upper()]


# Points each severity contributes to the risk total used for the letter grade.
SEVERITY_POINTS = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 10,
    Severity.HIGH: 40,
    Severity.CRITICAL: 100,
}


@dataclass
class Finding:
    """A single thing vetgate noticed.

    `trigger` is the provenance line — *when/why this would run or be read* — which
    is what makes a report actionable ("runs automatically when the folder is opened").
    `ref` is the git ref the finding was seen on ("working-tree" for the checkout);
    `only_on_ref` marks findings that exist on a non-checked-out ref and would be
    invisible to a normal tree scanner.
    """

    id: str
    title: str
    severity: Severity
    surface: str          # e.g. "claude-code", "vscode", "instruction-file", "watchdog"
    path: str
    detail: str
    trigger: str = ""     # provenance: when this executes / is loaded
    line: Optional[int] = None
    evidence: str = ""
    recommendation: str = ""
    ref: str = "working-tree"
    only_on_ref: bool = False
    tags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


GRADE_ORDER = ["A", "B", "C", "D", "F"]


@dataclass
class Grade:
    letter: str
    score: int                      # 0 = pristine, higher = worse
    counts: dict                    # {"CRITICAL": n, "HIGH": n, ...}

    @property
    def is_passing(self) -> bool:
        return self.letter in ("A", "B")


def grade_findings(findings) -> Grade:
    """Deterministic worst-case-aware letter grade.

    A letter grade is the thing people screenshot, so the mapping is intentionally
    blunt and worst-case-driven rather than an average that a pile of INFOs could
    dilute.
    """
    counts = {s.label: 0 for s in Severity}
    score = 0
    for f in findings:
        counts[f.severity.label] += 1
        score += SEVERITY_POINTS[f.severity]

    crit = counts["CRITICAL"]
    high = counts["HIGH"]
    med = counts["MEDIUM"]

    if crit >= 1 or high >= 3:
        letter = "F"
    elif high >= 1:
        letter = "D"
    elif med >= 3:
        letter = "C"
    elif med >= 1:
        letter = "B"
    else:
        letter = "A"
    return Grade(letter=letter, score=score, counts=counts)
