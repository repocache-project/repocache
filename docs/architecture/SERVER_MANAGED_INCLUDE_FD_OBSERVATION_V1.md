# Descriptor-relative managed include observation — read-only v1

**Primary issue:** [#31](https://github.com/teixemf/repocache/issues/31) · **Related:** #18 / #25 / #27 / #28 · **Target:** v0.6.0  
**Status:** IMPLEMENTED DIAGNOSTIC PRIMITIVE ONLY; native write/activation and protected-manifest provenance NOT VERIFIED.

The API repocache.server_managed_include_fd_v1.observe_managed_include_at(parent_fd) is a *read-only* local filesystem observation of the **fixed filename** repocache-managed.conf relative to a caller-opened directory descriptor. The function does not accept a pathname, caller-controlled basename, NGINX configuration, state generation or privilege token. It does not inspect an upstream repository, execute subprocesses, contact networks, install packages, write files, reload NGINX or publish the client catalog.

## Bounded observation contract

- Require a valid directory FD and reject writable-by-group/other parent directory metadata at the start and end of the read. It does **not** authenticate the FD's path, mount, ancestor ownership or source. A caller-provided directory FD can refer to an unrelated directory.
- Open the **literal basename** using descriptor-relative Linux openat with O_NOFOLLOW, O_NONBLOCK, O_RDONLY and O_CLOEXEC. Reject symlinks, hardlinks (nlink != 1), directories, pipes/special files, empty files, unexpected modes, cross-device leafs and files exceeding 256 KiB. Allow modes 0600, 0640 and 0644 only.
- Hash file bytes on the opened inode, with a bounded read. Recheck file fstat, non-following relative stat of the name and the pinned parent fstat; refuse observable changes of size, inode, device, mode, UID, GID, link count, mtime or ctime. This detects common replacement/in-place-change races but **does not eliminate all TOCTOU races** or bind a file to the live NGINX tree.
- Return a small FD_SNAPSHOT_ONLY result with observed digest, metadata and no secret content, or a reported absence. Errors contain static redacted codes. For **every** result, trusted_parent_ancestry_verified, protected_manifest_provenance_verified, authorizes_write, authorizes_nginx_reload and authorizes_catalog_publication are **false**.
- File uid is observed, **not accepted as proof of root ownership**; in ordinary unprivileged CI, a test-owned file is valid diagnostic evidence only. The prior [managed-include preview](SERVER_MANAGED_INCLUDE_PREVIEW_V1.md) separately rejects a non-root-owned observation, but its path field still requires independently proven binding.

## Explicit integration boundary

Do **not** feed these observations into privileged activation without a reviewed, trusted bootstrap that: (1) authenticates the intended installation and protected path and opens every ancestor with verified root ownership, mount/namespace policy and no symlinks; (2) obtains a protected transaction lock and trusted generation/manifest; (3) reads state and managed bytes from pinned FDs and detects drift, ACL/xattr and SELinux constraints as applicable; (4) stages and fsyncs only reviewed managed targets; (5) validates the *full effective* distro-packaged NGINX config with nginx -t, reloads under explicit authorization and verifies routing; (6) journals/rolls back any failure before atomically advertising verified active repositories. No result from this helper is a write token, an authorization assertion or an NGINX syntax verdict.

In particular, a caller may pass a directory descriptor opened from a symlinked/replaced ancestor or an unrelated mount. The fact that openat prevented following the **final** symlink does not prove safe absolute path ancestry. The fixed basename prevents this helper from being used as a general-purpose arbitrary file reader; it is not sufficient protection to permit invocation inside a generic root helper.

## Evidence / status

Focused test: pytest -q tests/test_server_managed_include_fd_v1.py. Tests use disposable, actual Linux directory FDs, symlinks, hardlinks, a FIFO, path replacement and in-place mutation. They are **not** real Debian/Alma installation or operational NGINX checks. Full original #31 and #18 acceptance remains **NOT VERIFIED**. The narrow owner-accepted native systemd/SELinux test exceptions from #25 remain **NOT VERIFIED — OWNER-ACCEPTED RISK**; no other functional or security requirement is waived.
