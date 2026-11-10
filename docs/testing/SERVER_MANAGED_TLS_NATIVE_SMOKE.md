# v0.6.0 — disposable server HTTPS/TLS smoke (#30)

## Scope

Run **real native NGINX** under disposable Debian 13 and AlmaLinux 10
containers. Generate test-only short-lived X.509 credentials. Validate
the server TLS endpoint using a private AF_UNIX SSL listener with
strict client-side certificate trust, SNI and hostname verification.
No firewall or external network port, OS service, real REPOCACHE
state, production NGINX configuration or operator secrets are touched.

## Executable evidence

The distro workflow installs the system NGINX and OpenSSL through
official APT/DNF sources in the ephemeral container. The pytest test
generates a fresh self-signed RSA-2048 certificate with DNS SAN
cache.example.invalid and mode-0600 private key under a temporary tree.
It runs real nginx -t on an isolated configuration, starts the separate
native foreground master and connects to the local Unix SSL socket
using Python SSLContext with that synthetic certificate as the only
CA and exact hostname validation. It requires a 200 response and
unchanged certificate/private-key bytes.

Negative cases independently refuse an untrusted CA and wrong
hostname at real TLS handshake. Missing certificates, missing keys,
mismatched keys and malformed PEM are rejected by actual nginx -t
before any new master is started. Test cleanup stops the disposable
master, preserving all host services.

Run inside a disposable supported distro container after installing
python3, python3-pytest, nginx, openssl and ca-certificates:

    PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -q -rs tests/test_server_https_tls_native_v1.py

The ordinary Python CI can SKIP tests when native NGINX or OpenSSL is
missing; the two OS-specific jobs must PASS at the exact reviewed SHA.

## Production contract and remaining gates

The approved v1 declarative deployment contract uses
deployment.tls.mode=operator-provided and distinct absolute
certificate_file/private_key_file references. Actual administrators
must provision trustworthy certificates and protected keys outside
REPOCACHE. The project must not bundle, overwrite, log or distribute
private keys; it must not request ACME certificates or open public
firewall ports implicitly.

This test does not establish installed signed NGINX/package provenance,
root/ACL/mount/SELinux trust, certificate issuer/expiry acceptance for
a real domain, active APT/DNF repository cache routes, crash-safe
configuration rollback, booted systemd, AlmaLinux SELinux enforcing or
owner-approved production exposure. These remain NOT VERIFIED under
issues #19/#25/#27/#28/#30/#31/#64. Disposable successful TLS
handshakes are narrower than a supported complete REPOCACHE server.

Original #30 criteria: both-distribution disposable HTTPS PASS only
after inspected CI; malformed/mismatched TLS rejection PASS only at
the isolated native syntax/handshake scope; real certificate/key
preservation, root-only production access, firewall/port safety and
native-host operation remain NOT VERIFIED.
