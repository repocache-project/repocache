# Disposable native TLS rotation and rollback under stock NGINX (#30)

A successful nginx syntax check or a reload return code does **not** prove
that a newly configured TLS identity is active or that a failed key pair
left an otherwise working route operational.

The isolated Debian 13 / AlmaLinux 10 CI starts unprivileged stock NGINX
on a loopback-only port using a disposable synthetic X.509 certificate,
performs a real trusted TLS handshake and records the peer DER fingerprint,
rejects a mismatched key pair via Python OpenSSL before attempting a reload,
changes the private candidate config to a separately generated certificate,
checks syntax, sends a reload, and **observes the new peer fingerprint
through TLS**. It then restores the original configuration, reloads again,
proves the original peer certificate is actually served and verifies every
original fixture cert/key byte and key permission remained unchanged.

The container has network isolation, no privileges, a read-only filesystem
except its private tmpfs, no production key material and no host NGINX.
The smoke is an actual test of **NGINX runtime TLS state transitions in
disposable userland**, not an authenticated managed configuration writer,
SELinux proof or safe root-level package transaction. Final #30/#19 native
booted host certificate provenance, controlled reload/rollback authorization
and firewall exposure remain NOT VERIFIED.
