# Trusted fixed os-release reference in native VM preflight (#26)

The read-only booted-VM preflight originally followed the distribution
`/etc/os-release` symlink without constraining its destination. An
unexpected symlink could make the preflight classify untrusted content as
the native OS identity, or follow a path outside the reviewed fixed read
set. A successful distribution-name match is not host provenance.

The reader now inspects the fixed root-owned non-group-writable ancestors
`/`, `/etc`, `/usr`, and `/usr/lib`. It accepts a private fixed
regular file at `/etc/os-release` or only the canonical distribution
link to `/usr/lib/os-release`. The selected regular file must be root
owned, uniquely linked, non-group-writable and bounded in size. The
actual read follows **no** symlinks: it opens the fixed selected regular
file using `O_NOFOLLOW`. Unexpected symlink targets, owner/mode
mismatches and unavailable references yield static `FIXED_READ_UNSAFE`
without exposing paths or bytes.

Unit regressions cover official Debian/Alma-style relative and absolute
links, direct regular files, path traversal, foreign links and mutable
regular files. Existing procfs/sysfs nofollow guards, container refusal,
non-authorizing reports and native read-only commands remain unchanged.

This is a Stage-A *negative trust hardening* change. It does not prove an
installed host root, verify signed OS or kernel identity, grant native
installation authority or substitute for the booted Debian 13 and AlmaLinux
10 systemd/SELinux #19 acceptance campaign.
