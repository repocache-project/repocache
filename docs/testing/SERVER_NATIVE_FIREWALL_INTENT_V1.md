# Explicit HTTPS firewall exposure intent — non-authorizing Stage A

Primary issue: #30, coordinating #26/#27, milestone v0.6.0.

The server installation schema has an optional Boolean firewall.modify
setting, defaulting to no host firewall modification. The new pure preview
returns a structured **review-only** description for the chosen canonical
HTTPS listen address and TCP port. It preserves opt-out by default, distinguishes
loopback, wildcard/unspecified, link-local and specific IPv4/IPv6 exposure,
and does not infer native OS identity from an untrusted distro string.
The Boolean is an administrator REQUEST, never authorization.

The preview never reads installed firewall policy, identifies an active
nftables/firewalld backend, executes iptables or firewall-cmd, writes rules,
modifies NGINX, changes firewall services or opens a socket. In particular a
requested wildcard bind still requires inspection of the existing policy,
operator authority, staged rule ownership, active listener, rollback and
distribution-specific tests. All production-authority flags remain false.
An explicit Boolean on a loopback-only listener requires no external port
opening in this *proposal*; it does not certify actual isolation.

The two supported Linux-distro disposable CI jobs execute the same negative
schema, forged-platform, IPv4/IPv6 and opt-out checks as an ordinary non-root
test suite. These are planning tests, not proof of booted host firewall
compatibility or privileged OS execution.

The complete original #30 requirement — operator-approved firewall behaviour
with NGINX/TLS/server ownership on real Debian 13 and AlmaLinux 10 with
enforcing SELinux — remains NOT VERIFIED until the final native acceptance
campaign under #19. No implicit firewall opening or host mutation is added.
