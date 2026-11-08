# Vendor NGINX systemd unit inventory — issue #27

This read-only, fail-closed inventory is a **partial precondition**, not a
service installer, privilege grant, systemd runtime test or authority to
reload an existing NGINX service.

## Exact inspected boundary

`src/repocache/server_native_nginx_service_unit_v1.py` reads only the
fixed stock distribution vendor file
`/usr/lib/systemd/system/nginx.service` (Debian 13 and AlmaLinux 10).
The on-disk file is opened with O_NOFOLLOW, a bounded length, regular
file/root-owned/non-world-writable/link-count checks and before/after inode,
mtime, ctime, parent metadata and name comparison. Fixed shadow unit and
drop-in candidates in `/etc/systemd/system`, `/run/systemd/system`
and the vendor unit drop-in directory refuse this initial-install
inventory. No arbitrary path/name/command is accepted.

AlmaLinux 10's official NGINX RPM intentionally installs **empty**
`nginx.service.d` directories in the vendor and administrator unit
hierarchies. Their existence is not an effective override. We accept only
empty, fixed-name, stable root-owned directories without symlinks, unsafe
parents, mount transitions or foreign entries, opened with directory
descriptors and rechecked after scanning. Any real file (including a hidden
file), unsafe permissions or changed inode blocks the clean-install
inventory. This explicitly distinguishes distro-installed empty directory
placeholders from an active, externally authored systemd drop-in.

The conservative content-shape check requires known distribution-native
NGINX start, validation-before-start, reload, forking and PIDFile entries,
plus `WantedBy=multi-user.target`. Unexpected executable paths, duplicate
sections, optional user/environment credentials or unrecognized extensions
are NOT VERIFIED / refused; this is **not** a systemd parser or proof
that an observed unit is the unit loaded by PID 1.

The public result always sets
`native_package_file_ownership_verified=false`,
`systemd_pid1_and_active_service_verified=false`,
`selinux_enforcing_service_verified=false`,
`authorizes_systemctl=false`, `authorizes_nginx_reload=false`
and `authorizes_native_package_installation=false`.
A PASS means solely that a bounded, conservative stock *file snapshot*
was observed. A future trusted host-root transaction must inspect native
package provenance, full unit resolution and effective drop-in hierarchy
again under its own authorization.

## Executed native package-manager fixture

`.github/workflows/server-native-nginx-metadata.yml` already installs
an authenticated native NGINX package with APT/DNF inside a **new
disposable Docker image** (not on the GitHub runner). The test driver
`scripts/smoke_server_native_nginx_container_install.py` now also calls
the read-only inventory after installation and associates the fixed
vendor `nginx.service` file with the exact native package owner:

- Debian 13: `dpkg-query -S` on the fixed /usr/lib and usrmerge
  /lib aliases, accepting only a single exact `nginx-common` or
  `nginx` ownership result.
- AlmaLinux 10: `rpm -qf --queryformat=%{NAME}` on the fixed
  vendor path, accepting only `nginx` or `nginx-core`.

The native APT/DNF signed-source checks execute independently before
the fixture installation. Package database ownership is **not**
cryptographic file integrity or authenticated host runtime identity.
The report records a fixed `nginx.service` SHA-256 digest for audit,
`vendor_nginx_systemd_unit_bounded_read_passed=true` and
`vendor_nginx_systemd_unit_distro_package_owned=true`, without
claiming native host service activation.

## Original release acceptance remains blocked

The test does **not** boot Debian 13/AlmaLinux 10 as a real systemd host,
start a systemd unit, validate effective systemd unit/drop-in state,
guarantee no other listener/service exists, verify AlmaLinux SELinux
enforcing, grant an administrator command, or perform an NGINX
reload/restart/rollback. The native package install is intentionally
confined to Docker with a hard explicit marker and a fresh OS namespace.

All full #27 requirements (fresh booted service, safe repeat installation,
conflict preservation and failure recovery), #64 least privilege,
#31 transactional rollback, and #19 true installed-system acceptance remain
**NOT VERIFIED** pending exact-revision execution on supported hosts.

No production host, installation script, release, signing-key, GitHub
protection or privileged system service configuration is modified.
