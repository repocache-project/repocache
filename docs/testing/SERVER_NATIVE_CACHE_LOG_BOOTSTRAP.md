# Fixed native NGINX cache and log directory provisioning (#29)

The v0.6.0 managed cache needs the exact
`/var/cache/nginx/repocache-managed` directory, and managed logs need the
exact `/var/log/nginx/repocache-managed` directory. This focused Stage-A
increment creates these two leaves with mode 0700 and fsyncs each leaf and
parent. It never creates or changes the distro's native NGINX parent
directories. It uses pinned O_NOFOLLOW directory descriptors and verifies
owner, group, mode, inode, device and ancestry around each operation.

The caller supplies a fixture root FD and expected UIDs. The first invocation
requires **both** leaves absent; partial preexisting state fails closed. On a
repeat, both leaves must match **exact persisted inode identity records**.
This permits retaining cached bytes and logs without deleting, truncating,
re-owning or traversing existing contents. For a real server, only an
independently authenticated, signed and locked protected ownership manifest
could supply such records; caller-supplied values alone are not authority.

If creation is interrupted after the first durable directory, the second
entry is refused pending a separately reviewed recovery procedure. A partial
creation is **not atomic**. A root-owned signed installer, NGINX worker UID,
package-owned ancestor check, root provenance, actual SELinux labels, runtime
writability, cache manager eviction, live log rotation and full installation
rollback remain NOT VERIFIED. This source is not part of the installed
server, does not authenticate the operator and cannot authorize production
host writes or destructive cleanup.

Tests use real filesystem descriptors, ownership checks and fsync under
disposable roots. Debian 13 and AlmaLinux 10 CI exercise the native
distributions' Python and the same fixture operations. Neither content
claim is a booted systemd or SELinux-enforcing VM result. Parent issue #29
remains OPEN and v0.6.0 remains NO-GO for actual host installation.
