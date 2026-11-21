# v0.6.0 native TLS identity copy/paste receipt (issue #30)

**Status:** read-only, non-privileged *partial evidence*, prepared before the
final coordinated booted-host campaign in #19. This probe is not a REPOCACHE
installer, an installed NGINX identity validator, a publisher-key validator,
or permission to reload NGINX, change SELinux or change the firewall.

Only run after the exact reviewed v0.6.0 source, installation and operator
certificate are already independently authenticated and safely active on a
snapshot-backed **Debian 13** or **AlmaLinux 10 (x86_64)** test VM. The
source checkout must be the same revision as the installed candidate. The
server must actually accept HTTPS on **loopback** at the chosen port; a
listener bound only to another interface cannot be verified by this probe.
Do not change its bind/firewall policy merely to satisfy the probe.

From the checked-out repository, using the distribution's ordinary
non-root Python, run (replace placeholder values locally):

```sh
/usr/bin/python3 -I scripts/inspect_native_vm_tls_v1.py \
  --hostname cache.example.invalid \
  --connect-ip 127.0.0.1 \
  --port 8443 \
  --ca-file /absolute/path/to/independently/reviewed/public-ca.pem
```

`--hostname` must equal the exact lowercase DNS SAN in the certificate and
is used as TLS SNI; a wildcard-only certificate is deliberately not accepted.
`--connect-ip` must be canonical loopback `127.0.0.1` or `::1`. Port must be
an exact TCP port in 1..65535. The optional `--ca-file` must be an absolute
path to **public** PEM CA material supplied through the operator's trusted
channel. Omitting it uses the machine's normal system CA set, which is not
proof that the installed CA set itself has approved provenance. Do not supply
private keys. Do not weaken certificate checking or trust an unreviewed
self-signed certificate as production evidence.

Copy the **single** `REPOCACHE_TLS_VM_V1=` line, and nothing else, into the
REPOCACHE conversation. The receipt reports only fixed status codes,
booleans and the negotiated TLS version. It excludes DNS names, addresses,
certificate paths, subject, issuer, key contents, TLS exception strings and
host identifiers. Exit code 0 means only a CA-validated TLS 1.2/1.3
handshake, Python/OpenSSL hostname verification and an **exact** DNS SAN
were observed at the loopback endpoint. It deliberately still records
`status: PARTIAL_EVIDENCE` and `issue_30_accepted: false`.

Exit code 2 produces a sanitized `NOT_VERIFIED` line: input refusal, a
non-loopback address, unavailable trust store or TLS identity refusal.
These failures must not be silently retried with disabled TLS checking.
Only run on trusted source. The receipt is not cryptographically signed,
and pasted text alone cannot authenticate the origin or prove an installed
server configuration.

**Remaining original #30 acceptance evidence:** on *each* booted test VM,
prove the installed service and exact loaded NGINX config correspond to the
approved candidate; test disposable HTTPS routes and negative host/SNI and
untrusted-CA handshakes; inspect independently approved certificate/key
ownership and modes without printing key contents; record before/after
certificate, key and firewall identities; verify exposed listeners and
operator-approved firewall intent, including AlmaLinux enforcing SELinux
labels; test rejected invalid/missing/mismatched key and failed reload
recovery without changing the previous working listener. Preserve the #19
install/rollback and #64 privilege/security gates. None of these extra
claims is made by this small socket probe.

CI evidence for the standalone formatter: `python3 -m pytest -q tests/test_native_vm_tls_probe_v1.py`, using a disposable locally generated
OpenSSL key pair and loopback Python TLS fixture. Running that test in a
container is **not** a booted host result, and its synthetic CA is **not** an
operator trust decision.
