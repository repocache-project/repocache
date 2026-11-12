# Read-only v0.6.0 server VM preflight (#26)

This Stage-A executable is **not** a server installer or installation readiness
certificate. Run only from independently authenticated and reviewed REPOCACHE
source. It is not yet distributed as a functional v0.6.0 server release.

From a Debian 13 or AlmaLinux 10 host with its OS-native Python, inspect a
locally reviewed deployment document (the example contains intentionally
unusable .invalid placeholders):

~~~sh
/usr/bin/python3 -I scripts/server_v06_preflight.py \
  --document /absolute/path/to/reviewed-server-install-v1.json \
  --intent inspect
~~~

Only absolute, single-link, regular input files are accepted. The document
must pass the existing exact install-v1 JSON contract. Symlinks, invalid UTF-8,
duplicate keys, oversized input and changes observed during read are refused.

All output is sanitized JSON with static check codes and guidance,
"read_only": true and "authorizes_installation": false. No secrets or
configuration path values are emitted. Exit 1 indicates an observed FAIL,
exit 2 invalid input/unavailable observation, and exit 3 incomplete
observations (NOT VERIFIED). Exit 0 is deliberately unavailable: this
diagnostic is not a successful installation gate. Neither diagnostic intent
performs package, systemd, NGINX, firewall, SELinux, TLS or state mutation.

Stage-B booted-native acceptance remains #19. Package provenance and NGINX
install remain #27, persistent state #31, root control and its independent
security review #64, repository lifecycle #95/#28, TLS #30, client APT/DNF
source writes #24, and authentic owner-signed candidate #76/#88.

A green CI job for this diagnostic is **not GO for VM installation**. Do not
attempt production installation or repocache-client repos sync --apply based
on this tool alone.
