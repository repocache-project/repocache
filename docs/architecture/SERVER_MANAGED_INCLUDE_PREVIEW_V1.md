# Managed NGINX include ownership preview — bounded v1 increment

**Tracking:** [#31](https://github.com/teixemf/repocache/issues/31), [#18](https://github.com/teixemf/repocache/issues/18), [#25](https://github.com/teixemf/repocache/issues/25) · **Target:** v0.6.0 · **Status:** READ-ONLY PREVIEW, NO PRIVILEGED IMPLEMENTATION.

`repocache.server_managed_include_v1.preview_managed_include()` provides an inert, deterministic comparison of the *proposed managed NGINX include* against supplied manifest/file observations. It does not inspect the host, execute NGINX, mutate an installation, allocate state generations or make an authorization decision.

## Contract

- Input is the existing strictly validated server-install v1 document, including its required `expected_state_generation`, together with an explicit `current_generation`, bounded UTF-8 candidate bytes, and optional caller-supplied prior manifest and observed-file snapshots.
- Manifest v1 names **only** `deployment.paths.generated_include`; it records `schema_version`, creation/update `generation`, exact `path`, lowercase SHA-256 of file bytes, `uid`, `gid`, `mode`, `dev`, `ino`. Observed-file snapshots add `kind` and `nlink`. Both are closed schemas. Root UID, safe known file modes, positive inode/device identities and a single observed hardlink are required. This is a *proposed comparison format*, not yet the protected state schema.
- If both prior manifest and observed file are absent, the preview reports `WOULD_CREATE`. An existing file without a manifest is **foreign and refused**, even when its contents match. A manifest with a missing file or mismatched digest, owner, group, mode or inode is **refused as drift**. A matching file may be `UNCHANGED` or `WOULD_REPLACE`.
- All output is fixed-shape and value-redacted; `authorizes_write`, `authorizes_nginx_reload`, `authorizes_catalog_publication`, `protected_manifest_provenance_verified`, `live_filesystem_ownership_verified` and `nginx_syntax_verified` are **always false**. Digest/paths/content are never returned.

## Security boundary / remaining gates

This pure function cannot prove that a caller's manifest came from root-protected state or that observations were captured securely. It **must not** be treated as a sufficient proof for root writes, file deletion, reuse of a path or service activation. The future privileged #27/#31 engine must use independently authenticated authorization, generation locking, a trusted manifest, descriptor-relative no-symlink and mount/hardlink checks, byte verification on the opened inode, staged files, full packaged `nginx -t`, controlled reload and durable rollback. #28/#95 still own verified repository route derivation and atomic discovery; do not advertise disabled/unverified mappings. DNS/upstream policy is being resolved separately, not by this module.

**Testing:** `pytest -q tests/test_server_managed_include_v1.py`. These are pure unit/synthetic observations. Debian 13 / AlmaLinux 10 native installation, systemd/SELinux and NGINX syntax/reload outcomes remain **NOT VERIFIED**. The two explicitly owner-accepted unavailable native demonstrations retain the narrow #25 risk decision; no other operational criterion is waived.
