# Pinned native TLS key pair in a private test root (#30)

The internal fixture-only function verifies a matching certificate/key by
passing previously opened Linux file descriptors through the procfs FD
interface to OpenSSL. The caller-supplied root FD and UID never authenticate
a production host or administrator. All directories/leaf inodes are pinned
O_NOFOLLOW, with exact owner, mode, same-device, single-link and unchanged
before/after metadata checks. The private key must be mode 0600. Unexpected
xattrs and SELinux contexts fail closed.

This checks cryptographic pair compatibility in disposable Debian 13 and
AlmaLinux 10, not chain issuer trust, SAN/hostname, expiry, production
certificate ownership or NGINX master accessibility. It never writes key
material or activates TLS. No SELinux enforcing booted system evidence or
signed root broker is implied. #30/#64/#19 stay open.

## Optional, fixture-only certificate identity and expiry check (Stage A)

The `fixture_ca_pem` argument tests a **real OpenSSL client/server TLS
handshake over bounded in-memory BIOs**, using the already FD-pinned server
certificate and private key. The client requires a valid DNS Subject
Alternative Name matching the validated listener hostname, OpenSSL-verified
certificate validity dates and a chain accepted by the supplied disposable
CA. A CN-only certificate, wrong SAN, untrusted test CA, expired leaf or
invalid/oversized CA input fails with a fixed, non-disclosing error code.

This does not open a TCP socket, fetch any network resource, write keys,
run a subprocess in the production code, modify systemd/firewall state or
authorize an NGINX reload. Real OpenSSL fixture tests on Debian 13 and
AlmaLinux 10 include positive SAN and negative issuer/SAN/expiry cases.

**Not production acceptance:** The caller may supply any fixture CA.
A passing test therefore cannot authenticate a host-trusted root/issuer,
an operator-approved certificate, the mounted host root, SELinux labels
or the production clock. The public production fields
`certificate_chain_verified`, `certificate_hostname_verified` and
`certificate_expiry_verified` deliberately remain false, even when
`fixture_ca_san_expiry_handshake_verified` is true. The original #30
native deployment and #19 VM acceptance criteria remain NOT VERIFIED.

## Exact DNS SAN, not wildcard hostname coverage (Stage A, #30)

A successful OpenSSL `check_hostname` handshake normally accepts a
wildcard DNS SAN such as `*.example.invalid` for a matching host.
The narrower REPOCACHE **fixture identity** contract requires an actual
DNS-type Subject Alternative Name **equal to the canonical validated
listener hostname**, compared case-insensitively. After the verified
in-memory TLS handshake, the checker inspects the authenticated peer
certificate's SAN tuple and refuses wildcard-only or CN-only identities
with its existing redacted error code. It never disables OpenSSL chain,
hostname or validity checks.

Real distro OpenSSL regression fixtures cover exact and upper-case DNS SANs,
wildcards that OpenSSL might otherwise accept, an expired signed certificate
and a correctly signed **not-yet-valid** certificate. A structurally valid
key/certificate pair cannot be treated as valid for a listener when
certificate validity has not begun.

This remains an opt-in, caller-chosen disposable CA test, not a new
installed-host certificate policy: an administrator may have legitimate
reasons to deploy a wildcard using a separately authorised real TLS trust
contract. No public CLI/production trust selector, OS CA installation,
firewall change or NGINX reload is enabled. Real operator issuer approval,
installed host clock/trust, systemd/SELinux and VM acceptance stay
NOT VERIFIED under #30/#19.
