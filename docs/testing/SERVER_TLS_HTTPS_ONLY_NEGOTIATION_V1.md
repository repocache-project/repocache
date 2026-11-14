# Native NGINX TLS protocol and plaintext isolation (Stage A)

Primary issue: #30, milestone v0.6.0.

This extends the existing native TLS listener test without changing the
installed listener policy, operator credentials, certificate paths, CLI or
firewall. Both Debian 13 and AlmaLinux 10 disposable jobs run the test.

In addition to the existing positive synthetic operator certificate HTTPS
client, hostname mismatch and unrelated CA refusal tests, the smoke now
creates strict TLSv1.2-only and TLSv1.3-only clients with certificate and
DNS-name verification enabled. It confirms a successful native NGINX
response for each exact negotiated protocol. A raw plaintext HTTP request
to the HTTPS-only listener must not return the protected response body.
NGINX may legitimately return a 400 diagnostic to that plaintext request.

All tests use synthetic disposable private keys in a private container and
localhost sockets. No real certificate, key, firewall, APT/DNF source or
installed host NGINX is accessed.

NOT VERIFIED: installed host certificate chain, DNS SAN and expiry, real
operator-provided private key, key ownership and SELinux context, systemd,
actual port exposure, firewall authorization, repair/reload and signed
release. These requirements remain owned by issues #30 and #19. A
successful CI handshake does not authorize host listener activation.
