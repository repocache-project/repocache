# Signed native storage roots and dedicated service sandbox (#29)

The existing explicit authenticated NGINX activation prepares two fixed,
owner-marked directories while the existing protected state lock is held,
after signed worker/package/configuration checks and before systemd start:
`/var/cache/nginx/repocache-managed` (packaged worker UID/GID, 0700) and
`/var/log/nginx/repocache-managed` (root:root, 0750). The signed unit keeps
ProtectSystem=strict, with only these exact directories added to its
existing runtime-directory write exception. Parent directories and
/etc/nginx must remain read-only in the actual master's mount namespace;
the two permitted leaf mount views must identify the same host inodes.

The root-owned parent contains a separate 0600 inode/ownership marker for
each root. Both roots are preflighted before creation. Symlinks, unowned
or incomplete roots, changed marker contents, writable ancestry, foreign
mount boundaries (including same-device bind mounts), extra xattrs and
read-only storage are refused. Repeat activation verifies rather than
recreates, relabels or deletes existing data. A partial mkdir/marker
interruption fails closed and requires operator inspection; no automatic
adoption or deletion is authorized.

On AlmaLinux 10, enforcing SELinux is mandatory. Stock policy lookup
must give httpd_cache_t and httpd_log_t respectively; only newly created
inodes may be assigned their matching policy context through the pinned
descriptor. Existing mismatched labels fail closed; no policy changes,
recursive relabel, setenforce or permissive workaround. The package
installer also validates the fixed cache parent, including a label
assignment only when it itself created that parent.

This is not a second root-control protocol. The existing signed installer
retains its lock, and a failed post-start mount observation uses its
existing compensation. The fixture-only storage APIs remain unchanged.
No per-repository cache activation, metrics-file creation/rotation,
automatic pressure decision, signed client fallback, full repair or
publisher acceptance is claimed. Booted tests must establish the actual
unit mount restrictions and label support on both target distributions;
actual confined NGINX worker cache/log access is a subsequent managed
configuration transaction gate.
