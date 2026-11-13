# Fixed native NGINX cache and log namespace provisioning (#29)

This Stage-A fixture-scoped module creates two *real* fixed Linux directory
trees required by the v0.6.0 server configuration:

- /var/cache/nginx/repocache-managed — NGINX worker UID/GID, mode 0700
- /var/log/nginx/repocache-managed — root-owned with mode 0750

The new \`server_native_storage_bootstrap_v1\` internal API accepts a *fixture
root FD*, root UID, and expected native distro worker UID/GID; it does **not**
accept arbitrary paths, package names, config snippets or a source URL.

## Security and preservation

Native NGINX cache files are owned by the actual unprivileged worker in both
supported distro container jobs. The root-owned log subtree denies NGINX
worker writes. Root-owned **external** durable ownership markers under
/var/cache/nginx and /var/log/nginx preserve exact dev/inode/UID/GID/mode
identity of their managed child directories; the worker cannot replace the
marker by writing inside its own cache. The root-owned parent and each
ancestor are traversed by pinned descriptor/O_NOFOLLOW operations and strict
ownership/mode/same-device checks. Marker files are single-link, mode 0600,
canonical bounded JSON and fsynced before success.

A first provisioned directory without a durable marker, an existing unmarked
directory, a marker without a child, a changed inode/owner/mode, an unsafe
ancestor, a symlink, a hardlinked marker or unreviewed ACL/xattrs including
security.selinux **fail closed**. Partial crash state is never deleted or
silently adopted. A fully marked cache root persists across re-entry and
retains existing cache files/log history; the implementation never runs
recursive cleanup, changes package managers, modifies NGINX configuration,
starts services, changes firewall/TLS or writes any source file.

This first-stage function deliberately compares an FD with the current live
namespace root and **refuses the real /**, even inside Docker. It only
modifies detached temporary fixture roots. A caller-provided UID or path
descriptor is never proof of host-root, owner/operator approval or signed
NGINX package identity. The packaged Debian NGINX worker is www-data;
AlmaLinux 10 uses the native nginx worker. The CI script obtains the actual
installed passwd UID/GID, creates a detached temporary filesystem, and
forks a process which drops to the real distro worker identity to prove it
can write cache files but cannot write the protected log root. It then tests
repeat install preserving worker-created bytes and the independent read-only
cache free-space probe. Both distro NGINX packages receive an actual nginx -t.

## Remaining original #29 gates

**NOT VERIFIED:** installed source/package provenance and native worker
identity authentication; creation of per-repository cache directories; real
host mount/SELinux enforcing labeling and access policy; NGINX cache HIT/MISS
with a booted systemd service; logrotate/metrics records and retention; disk
pressure/fallback enforcement; comprehensive same-version repair; signed
server candidate and booted VM GO. Production labeled directories are
deliberately refused until an SELinux-preserving implementation is reviewed.

This is no installed root helper, no operator CLI and no authority to call
the test API on a real server. Parent #29/#25/#19 remain OPEN. Converge with
#27/NGINX and #31 state-WAL ownership before any production activation.

CI: .github/workflows/server-native-storage-bootstrap.yml
Tests: python3 -m pytest -q tests/test_server_native_storage_bootstrap_v1.py

## Cross-root preflight before first mutation (CI Stage A)

The fixed cache and log roots are an inseparable first-install proposal.
The fixture-scoped bootstrap now checks both parents and any *existing*
directory/owner markers with pinned FDs **before either first mkdir, chown
or marker creation**. An unsupported foreign log root, a mismatched owner
marker, a symlink, or an ACL/xattr denial on the log side must not leave
a newly created cache directory on the other side. The normal write-stage
validation still repeats inode, ownership, mode and marker checks to
refuse changes between preflight and commit; this read-only first pass
is not a TOCTOU authorization or a cross-filesystem atomic commit.

Negative tests exercise real filesystem foreign root preservation,
corrupt/symlinked markers, unchanged cached bytes after rejected rerun,
and successful repeat provisioning on both supported distro containers.
Partial failure **during** mkdir/chown/fsync still requires the existing
explicit reconciliation; the code never recursively removes cache data.
Actual host-root authority, NGINX UID/GID provenance, SELinux enforcing
and installed service operation remain NOT VERIFIED until the final
native campaign and independently approved privileged installer.
