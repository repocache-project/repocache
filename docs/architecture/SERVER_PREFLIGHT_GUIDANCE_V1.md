# Read-only native preflight diagnostic guidance v1 (#26)

This is an **inert presentation-only increment** for the existing partial
`server_preflight_v1` reports, not a deployment preflight command or install
authorization.

`explain_native_preflight(report)` returns deterministic dictionaries with
allowlisted `check`, `status`, `code` and static, actionable English
`guidance`. It refuses forged code/status triples, requires guidance for
every registered check and does not interpolate paths, OS-release content,
credentials, package metadata, repository URLs or other host values.
The original report remains non-authorizing: `all_verified=False` and
`authorizes_installation=False`.

APT/DNF **package availability, repository trust and signature enforcement**
are owned by issue #27. This increment does not run apt-get, dnf, metadata
updates, network probes, privileged operations or filesystem writes.
The online Python dependency profile (#79/#83/#84) remains separate.
Future operator CLI integration must be coordinated with #107/PR #209 and
cannot claim that this library proves a complete server installation.

Issue #26 remains **OPEN / NOT VERIFIED** until its other original criteria,
including the cross-issue missing-package diagnostic evidence from #27, are
satisfied. The maintainer-accepted limited booted systemd/SELinux test-risk
exception remains unchanged. No release, signing or deployment authorization.
