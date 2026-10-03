"""vetgate — catch what your AI coding agent silently trusts.

Two things no other free tool does:
  * a continuous *personal-config watchdog* over your own ~/.claude, ~/.cursor,
    ~/.vscode ... that tells you "this changed — was it you or the agent?"
  * an *all-branches / all-refs* sweep that finds auto-run payloads hidden on a
    non-default branch, where a checked-out-tree scanner can never see them.

Everything else (cross-convention preflight inventory, instruction-file threat
analysis, the A–F trust grade, the CLI / pre-commit / GitHub Action /
SessionStart-hook surfaces) is table-stakes plumbing around those two wedges.
"""

__version__ = "0.1.0"

from vetgate.model import Finding, Grade, Severity  # noqa: E402

__all__ = ["Finding", "Grade", "Severity", "__version__"]
