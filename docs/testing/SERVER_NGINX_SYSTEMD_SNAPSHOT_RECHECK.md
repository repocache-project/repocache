# Recheck effective systemd NGINX unit after kernel master observation (#27)

A one-shot `systemctl show nginx.service` snapshot can become stale while a
subsequent read of the reported MainPID examines the kernel executable and
process inode. A service restart or unit override during that gap must not
silently be represented as a stable active NGINX identity, even in the
read-only native prerequisite report.

The observer now performs a second **identical fixed-name, bounded,
read-only** `systemctl show` query after the existing kernel executable
inode check. It requires the complete parsed unit property map (including
MainPID, FragmentPath, DropInPaths, ActiveState and NeedDaemonReload) to
match the first observation byte-for-byte at the semantic property level.
A changed PID or property, command timeout or invalid response refuses with
a static error; no partial or positive observation is returned.

Unit tests simulate a MainPID replacement, new foreign drop-in, service
becoming inactive and a daemon-reload requirement between the two queries,
while preserving the original valid vendor unit and kernel-process checks.
No dynamic service names, systemctl writes, root worker, NGINX restart,
reload, package transaction or catalogue publication are introduced.

The result is still an *instantaneous, non-authorizing snapshot*; another
race after the second query remains possible. A future #31 privileged
transaction must hold its protected state lock, revalidate the live service
and reconcile actual post-reload route exposure. Final #19 booted Debian 13,
AlmaLinux 10 systemd/SELinux acceptance remains NOT VERIFIED.
