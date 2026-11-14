# Native NGINX payload scratch root ownership — #27

The native APT/DNF download-only rehearsal inventories candidate archives
from an isolated per-probe directory. It now refuses a download root that is
not owned by the active UID or is group/world-writable, **before reading any
payload inventory**. Previously only the child archive inodes were checked;
a writable root could allow a cooperating process to substitute entries
between observations. The root symlink and type checks, child inode/type,
link-count, maximum artefact count and aggregate size checks remain. The
fixture exercises DAC mode and owner-refusal without executing a native
install. This closes one trust-boundary gap but does not authenticate the
publisher, eliminate all kernel races, or authorize using scratch downloads
for host package installation. Owner signing and the final Debian 13 /
enforcing AlmaLinux 10 campaign remain separate.


## Refuse ambiguous duplicate native package identities (#27)

The download-only native NGINX rehearsal now rejects any pair of .deb or .rpm
payloads whose authenticated package metadata claims the **same package
name**, even if both individual payloads are otherwise accepted by the
native metadata/signature probe. Different versions or architectures of
the same package would be ambiguous installation inputs; a successful
download is not permission to select one implicitly. The result is the
static `NATIVE_PAYLOAD_SET_UNSAFE` code, with zero accepted payloads and
no installed-host authority.

Both Debian and AlmaLinux implementations use the same name-set rule.
Unit tests cover deliberately duplicated and distinct names through
controlled native metadata command output; the separate real distro
download-only CI continues to exercise authentic OS package metadata.

The test fixture never weakens signed APT metadata, RPM `rpmkeys`
authentication, directory ownership, archive download limits or native
package-manager execution policy. The actual privileged package install,
verified service/SELinux and recovery journal remain NOT VERIFIED under
the original #27/#31 and final #19 acceptance requirements.
