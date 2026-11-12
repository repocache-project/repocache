# Read-only native cache free-space observations v1 (#97)

This Stage-A module connects actual descriptor-bound Linux filesystem free-space
and inode observations to the existing pure cache-pressure policy preview.
It uses a fixed namespace, no JSON-specified path and no subprocess, package
manager, socket, root helper, NGINX reload or mutating filesystem action.

The internal testable entry point, observe_cache_pressure_under_root, consumes
a caller-supplied root descriptor and expected UIDs. **Those arguments do not
authenticate the host or authorize a write.** The future installed worker must
independently authenticate host-root provenance, installed release identity,
ownership manifest, root and NGINX UID policy, mount boundaries and SELinux.
The default read-only inspector conservatively requires a root-owned leaf
rather than guessing the packaged NGINX UID. All unexpected existing paths,
ownership, symbolic links and separate filesystem mounts produce an UNKNOWN
observation. Existing cache contents are never deleted or modified.

Both the root and cache leaf are opened with O_NOFOLLOW and descriptor-relative
fixed path components. The leaf is rechecked against directory metadata and
statvfs runs against its pinned FD. Real positive and negative Linux test
fixtures exercise the read-only behavior, missing/foreign/symlink paths,
bounded free-space/inode reports, exhaustion and hysteresis.

The result uses status READ_ONLY_CACHE_PRESSURE_PARTIAL and always reports
authorizes_installation=false. Free bytes are *not* cache occupancy or cache
manager eviction proof. POSIX modes cannot establish actual NGINX write access,
SELinux approval or package-manager fallback; therefore a high free-space
observation alone cannot yield a NORMAL state. Inode exhaustion is CRITICAL;
unavailable observations are UNKNOWN, never zero/free or a clean host.

Still NOT VERIFIED: native packaged NGINX policies and manager timing, cache
isolation and ownership, storage paths and SELinux enforcing, ENOSPC behavior,
actual upstream fallback, real warning/alert integration, idempotent clean
installation and booted VM evidence. Parent #97 remains OPEN; this module is
a non-activating prerequisite for #29/#25 and final #19 acceptance, not a
ready-to-install or release acceptance claim.

Test: python -m pytest -q tests/test_server_cache_pressure_observe_v1.py
