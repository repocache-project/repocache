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
mtime, ctime, parent metadata and name comparison. Fixed shadow units
and drop-in candidates across the standard systemd system-unit search path
refuse this initial-install inventory: D-Bus `system.control`, transient
units, generators (including early/late), administrator `/etc` and
`/usr/local/lib` units, attached directories, runtime `/run` units,
and the vendor directory. Both `nginx.service.d` and type-wide `service.d`
overrides are checked. Implicit NGINX service dependency directories
`nginx.service.wants`, `nginx.service.requires`, and `nginx.service.upholds`
are also refused across each fixed system-unit root and vendor root:
systemd can add dependent services from symlinks in those directories
without modifying the principal unit bytes. Empty dependency directories
are conservatively refused; only empty, safely owned `.d` drop-in
placeholders may be ignored. A full vendor file snapshot can otherwise
appear safe while PID 1 loads a higher-priority, independently managed
unit or extra dependencies.
No arbitrary path/name/command is accepted.

This static path inventory is conservative but **not authoritative** for
a running host: compile-time paths, manager environment, aliases, unit
load state and effective merged drop-ins must be checked separately
against booted systemd before service ownership or a privileged reload.
See [systemd.unit unit load paths](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit).
No new installation or service authority is granted.

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


## Fail-closed systemd directive allowlist

The read-only unit-shape parser now rejects **all unknown sections and
directives**, not only unrecognized `Exec*` commands. These other directives
can still change an otherwise familiar NGINX service: dependencies can start
unrelated units, bind mounts or credentials can expose root-owned data, and
environment/capability settings can alter executable behavior. Only the
observed distro-compatible `[Unit]`, `[Service]` and `[Install]` fields
are eligible; dependencies, optional service flags and service executable
arguments are constrained to known benign values. Unexpected aliases,
privilege, namespace, dependency or file/mount settings fail closed.
This is a conservative **syntax-shape observation**, not a replacement for
systemd's parser or an authorization of an effective loaded unit.

### Debian 13 native unit cross-check

The installed Debian 13 `nginx-common` unit uses the systemd key
`ConditionFileIsExecutable=/usr/sbin/nginx` (not merely
`ConditionPathExists`). This exact native executable test is allowlisted
without accepting a caller-supplied path or general `Condition*`
directives. The value was independently checked against the Debian
source distribution's official
[nginx-common.nginx.service](https://sources.debian.org/src/nginx/1.26.3-3%2Bdeb13u7/debian/nginx-common.nginx.service/).
Runtime compatibility still requires the exact supported distro CI.


## Effective PID1 `nginx.service` runtime preflight (read-only prerequisite)

A vendor unit stored under `/usr/lib/systemd/system` is **not** proof of
the unit loaded by an actual systemd PID1. The new independent,
non-authorizing `server_native_nginx_effective_unit_v1.py` observes
`nginx.service` using only fixed, non-shell
`/usr/bin/systemctl show --no-pager --property=... nginx.service`
arguments, bounded 5-second timeout, a fixed sanitized `PATH` and
`LC_ALL=C` environment and `cwd=/`. The command cannot write a unit
file, start a process, install NGINX or reload its service.

Execution first requires the existing read-only #27 vendor unit inventory
to report a valid, root-owned, unshadowed native unit. The systemctl
executable and every fixed ancestor must be root-owned, non-group-writable,
non-symlink and of the expected file/directory type. The returned
key/value response is strictly parsed, bounded and must match exactly
`Id=Names=nginx.service`, the fixed vendor `FragmentPath`,
no effective `DropInPaths`, loaded/active/running state,
`CanReload=yes`, `NeedDaemonReload=no` and a positive bounded
`MainPID`. Reordered keys are acceptable, but duplicate, extra,
unknown, conflicting, absent or malformed keys fail closed.
Errors contain only static codes, not stderr/output or private paths.

**Only a read-only observation:** systemctl output is not an authenticated
receipt, and this code does not independently prove process executable
inode, installed package owner trust, a real booted host, native systemd
PID1 provenance or SELinux enforcement. Its report explicitly sets those
flags and `authorizes_systemctl`, `authorizes_nginx_reload` and
`authorizes_nginx_install` to **false**. Mocked positive unit tests on
the exact source SHA prove parser and subprocess-refusal contracts only.
The future #64 fixed-operation root worker must revalidate *all* native
package/source/host/SELinux/NGINX ownership and read-only effective
state immediately before any real controlled reload, then verify the
actual running exposure and journal/compensation. A successful systemctl
show alone cannot authorize a protected transition.

Real booted Debian13 and AlmaLinux10 host unit checks and enforcing
SELinux evidence remain **NOT VERIFIED**; a disposable image with NGINX
installed but no systemd PID1 cannot certify them. Do not enable systemd
or modify an actual host based on this source.


## Additional fixed MainPID kernel-executable precondition

The effective-service observer now independently checks the reported
`MainPID` against a narrow, non-authorizing kernel /proc snapshot before
returning a positive read-only result. It refuses PID 1, non-root process
ownership, untrusted or mutable /usr/sbin/nginx executable metadata,
a different running executable inode, an unexpected /proc/<PID>/comm name,
and detectable process or executable inode changes between two observations.
All paths are built from the strictly parsed numeric MainPID; there is no
caller-supplied command, path, executable or reload. This is a **necessary
read-only identity observation**, not process attestation: PID reuse and
procfs races remain possible, package ownership or cryptographic binary
integrity is not established, and container PID1 is not native host evidence.
`kernel_nginx_master_executable_inode_observed=true` has no authority
semantics. `real_pid1_and_nginx_process_verified=false`, all mutation/
reload flags false and all original native #27 acceptance gates remain
NOT VERIFIED. A future privileged operation must independently reobserve
and pin relevant identities under its own authenticated transaction lock.


## Real disposable NGINX master inode smoke (not a native host service)

The native package-install CI now launches a **listener-free** NGINX master
using the distro's installed binary and a 0700 temporary private configuration
inside the already explicitly marked fresh Debian 13 / AlmaLinux 10 Docker
container. The process is a direct child, never a systemd nginx.service;
no systemctl, production host config, root worker, client catalog or network
listener is involved. Before and while the child runs, the read-only MainPID
helper must match the kernel's /proc executable device/inode to the installed
root-owned /usr/sbin/nginx, observe the nginx process name and reject
stale/incorrect kernel process identity. The exact disposable child is always
terminated and reaped within a bounded timeout. The JSON record explicitly
sets all host-root, native systemd, SELinux, reload and catalog authority
claims to false. This supports the low-level executable-inode invariant;
it **does not** satisfy #27/#31/#64 booted native acceptance.

The inode precondition also refuses a non-executable native binary mode or
a detected replacement of the fixed installed binary path between the first
and second kernel observations. This narrows accidental races but remains
insufficient for binary signing, authenticated package ownership, host-root
or real NGINX activation authority.
