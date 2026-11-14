# v0.6.0 complete-server candidate source inventory (Stage A)

**Purpose:** prepare a closed, version-specific source-member inventory for
the first usable REPOCACHE server release, tracked by #76 and #25. This change
does not authorize a release or claim an installable, signed production server.

The immutable public v0.4.0 source archive inventory remains unchanged in
`scripts/build_release.py:FILES` and `repocache.upgrade.RELEASE_FILES`.
The new v0.6.0-only inventory is explicitly enumerated at both the builder and
strict extraction boundary, including currently tracked server and client
Python modules, a validation-only server preflight, read-only native candidate
diagnostics, and the inert server configuration example.

Unreviewed `*.py` files are **not** automatically added to a release by a
filesystem glob. New first-party Python files require a reviewed inventory
update. Tests require every checked-in server/client module to appear in the
v0.6.0 set, enforce build/extractor parity, reproduce candidate tar bytes,
verify archive sizes and refuse missing/foreign archive members.

For the v0.6.0 target this is **only source completeness**. It does not prove:

- that all proposed modules are production-authorized or wired into an installed
  root-owned broker, state transaction, native NGINX/systemd/SELinux service,
  repository activation, client writer or rollback;
- a completed current-version bump, signed legacy eight-asset wheelhouse,
  publisher provenance or approved private-key use;
- successful final clean install, repair, real signed APT/DNF/cache requests,
  native Debian 13/AlmaLinux 10 VM operation or publication acceptance.

The test fixture synthesizes version metadata in a temporary directory only;
it never modifies `pyproject.toml`, `release-policy.json` or a release tag.
Before a real candidate may be built or published, #25/#19/#64/#76/#88 gates
must be met and the approved authoritative versioned installation contract
must be reviewed at its final source SHA.
