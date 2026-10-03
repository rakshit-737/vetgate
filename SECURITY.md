# Security policy

## Reporting a vulnerability
Please open a [private security advisory](https://github.com/rakshit-737/vetgate/security/advisories/new)
rather than a public issue. You'll get an acknowledgement within a few days.

## Scope & honest limits
vetgate is a **detection aid, not a guarantee.** It reduces the chance that an auto-executing
or instruction-injection surface slips past you; it cannot prove a repo is safe. A clean report
means "none of vetgate's checks fired," not "this workspace is safe to trust." Always combine it
with least-privilege agent settings and a sandbox for untrusted code. See the *Known limitations*
section of the README for specific evasions vetgate does not yet catch.

vetgate runs entirely locally and makes no network calls in its default (core) mode.
