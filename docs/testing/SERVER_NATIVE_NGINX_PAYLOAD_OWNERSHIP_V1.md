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
