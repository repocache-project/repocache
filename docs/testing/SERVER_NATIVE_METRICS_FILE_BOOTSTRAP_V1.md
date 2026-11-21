# Durable private NGINX metrics log inode (fixture-only Stage A)

**Primary issue #29; related #14/#31, milestone v0.6.0.**

The existing metrics renderer and real-NGINX rotation tests prove that
private opt-in logs are required, but the installed NGINX worker must never
create a missing file with ambient service-default permissions. This
fixture-only primitive provisions the fixed metrics.jsonl inode as owner
0600 and durably binds its identity to a separate root-owned canonical
marker in the existing protected NGINX log parent.

Before the first write it verifies the closed installer-owned log root
and its existing durable owner marker, denies foreign directories,
unsupported modes/ACL/xattrs and partial pre-existing file/marker pairs.
The detached root and every pinned log ancestor must also have no
unreviewed extended attributes; a refusal preserves both the attribute
and any existing historical log bytes and marker. This is a conservative
fixture gate, not an installed SELinux policy or label repair mechanism.
It opens relative to fixed pinned directory FDs with O_NOFOLLOW and
O_EXCL, fsyncs file and directories, then persists a 0600 owner marker
with device/inode/UID/GID/mode. Repeat execution checks the marker and
file identity, retaining all historical bytes, owner and inode. A crash
after file creation but before marker publication refuses all automatic
adoption, cleanup or repair. A complete post-marker crash is replayable.

This primitive refuses an FD for the actual current mount namespace's
root. The root UID and owner GID are fixture-supplied, not a host privilege
or trust proof. No CLI, service unit, logrotate file, nginx config or
production writer consumes it. It never authorizes a host action.

The dedicated two-distribution CI runs actual filesystem inode,
symlink/hardlink, foreign-file, marker-spoof, crash/restart and mode
refusals. Installed server root identity, true NGINX worker access,
owner approval, real systemd log rotation, SELinux enforcing and booted
Debian 13 / AlmaLinux 10 acceptance are **NOT VERIFIED** and remain in
#29/#19. An installed root worker will need a separately authenticated,
lock-coordinated implementation and explicit SELinux ownership handling.

## Controlled detached rotation reconciliation

Stock logrotate renames the marked inode to `metrics.jsonl.1` and creates
a new private inode. The original bootstrap must refuse an unrecognized
successor until the separate fixture reconciliation checks the exact old
inode in the private single-link archive and an empty, equally private
successor. The reconciler holds the existing protected fixture lock,
requires an otherwise empty state namespace, stages only the new marker,
fsyncs and atomically replaces the old marker. It replays a complete
identical stage after interruption, but refuses a partial, foreign or
nonempty successor. Both archives and the current log are never rewritten.
Actual logrotate tests use the generated candidate with a test-only no-op
reopen hook; two rotations retain the compressed archive and repeat
bootstrap accepts the new marked inode. This is **not** installed logrotate
integration: actual worker reopen, authenticated host/state locking and
SELinux policy remain mandatory and the live root is refused.
