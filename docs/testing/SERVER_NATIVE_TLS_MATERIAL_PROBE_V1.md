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
