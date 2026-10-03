"""All-refs / history sweep — the headline wedge.

Every competing scanner inspects the checked-out tree (or at most one named branch).
A keyv-worm-style payload planted on a *stale or non-default branch* is therefore
invisible to them: it never touches your working directory, yet it ships in the repo
and runs the moment someone checks that branch out or an agent is pointed at it.

vetgate enumerates every local branch, remote-tracking branch and tag, pulls the
blobs of known execution/instruction surfaces on each ref, and runs the exact same
`analyze_file` detectors over them — flagging anything that is NOT present in the
working tree as `only_on_ref` (the "hidden on a branch you never checked out" catch).
"""
from __future__ import annotations

import hashlib
import os
import subprocess
from typing import Dict, List, Optional

from vetgate.model import Finding
from vetgate.surfaces import MAX_BYTES, analyze_file, is_sensitive_path


class GitError(RuntimeError):
    pass


def _git(root: str, *args: str, timeout: int = 20) -> str:
    # Defense-in-depth: neutralize config-driven code paths (fsmonitor, pager,
    # aliases, system/global config) even though the read-only plumbing we use
    # does not trigger them. Never runs a shell; args are passed as a list.
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
    hard = ["-c", "core.fsmonitor=false", "-c", "core.pager=cat", "-c", "core.hooksPath=/dev/null"]
    try:
        res = subprocess.run(
            ["git", "-C", root, *hard, *args],
            capture_output=True, encoding="utf-8", errors="replace", timeout=timeout, env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise GitError(str(e))
    if res.returncode != 0:
        raise GitError(res.stderr.strip() or f"git {' '.join(args)} failed")
    return res.stdout


def is_git_repo(root: str) -> bool:
    try:
        return _git(root, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except GitError:
        return False


def list_refs(root: str) -> List[str]:
    """Local branches, remote-tracking branches and tags (deduped, HEAD first)."""
    out: List[str] = []
    try:
        head = _git(root, "rev-parse", "--abbrev-ref", "HEAD").strip()
        if head and head != "HEAD":
            out.append(head)
    except GitError:
        pass
    try:
        raw = _git(root, "for-each-ref", "--format=%(refname:short)",
                   "refs/heads", "refs/remotes", "refs/tags")
    except GitError:
        return out
    for line in raw.splitlines():
        r = line.strip()
        if r and r not in out and not r.endswith("/HEAD"):
            out.append(r)
    return out


def _ls_tree(root: str, ref: str) -> List[str]:
    try:
        raw = _git(root, "ls-tree", "-r", "--name-only", ref)
    except GitError:
        return []
    return [p for p in raw.splitlines() if p and is_sensitive_path(p)]


def _show_blob(root: str, ref: str, path: str) -> Optional[str]:
    spec = f"{ref}:{path}"
    try:
        size = _git(root, "cat-file", "-s", spec).strip()
        if size.isdigit() and int(size) > MAX_BYTES:
            return None
    except GitError:
        return None
    try:
        return _git(root, "show", spec)
    except GitError:
        return None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def working_tree_blobs(root: str) -> Dict[str, str]:
    """{relative-path: sha256} for sensitive files in the checkout, so the sweep can
    skip files that are byte-identical on another ref and surface only the delta."""
    blobs: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        if os.path.basename(dirpath) == ".git":
            dirnames[:] = []
            continue
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace("\\", "/")
            if not is_sensitive_path(rel):
                continue
            try:
                with open(os.path.join(root, rel), "r", encoding="utf-8", errors="replace") as fh:
                    blobs[rel] = _sha(fh.read())
            except OSError:
                blobs[rel] = ""
    return blobs


def sweep_refs(root: str, max_refs: int = 60, skip_working_ref: bool = True):
    """Return (findings, meta). Findings on non-working refs get ref=<name>;
    those whose path is absent from the working tree are marked only_on_ref=True.
    `meta` reports coverage so nothing is silently truncated.
    """
    root = os.path.abspath(root)
    meta = {"refs_total": 0, "refs_scanned": 0, "truncated": False, "error": None}
    if not is_git_repo(root):
        meta["error"] = "not a git repository"
        return [], meta

    refs = list_refs(root)
    meta["refs_total"] = len(refs)
    wt_blobs = working_tree_blobs(root)
    try:
        head = _git(root, "rev-parse", "--abbrev-ref", "HEAD").strip()
    except GitError:
        head = ""

    findings: List[Finding] = []
    scanned = 0
    for ref in refs:
        if scanned >= max_refs:
            meta["truncated"] = True
            break
        if skip_working_ref and ref == head:
            # working tree is covered by scan_tree(); still counts as scanned
            scanned += 1
            continue
        for path in _ls_tree(root, ref):
            blob = _show_blob(root, ref, path)
            if blob is None:
                continue
            # Skip files that are byte-identical to the checkout: the sweep's job is
            # to surface what is NEW or DIFFERENT on a ref you have not checked out.
            if path in wt_blobs and wt_blobs[path] == _sha(blob):
                continue
            hidden = path not in wt_blobs
            for f in analyze_file(path, blob, ref=ref):
                f.only_on_ref = hidden
                findings.append(f)
        scanned += 1
    meta["refs_scanned"] = scanned
    return findings, meta
