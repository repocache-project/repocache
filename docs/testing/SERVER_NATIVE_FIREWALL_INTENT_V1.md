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


## IPv4 reserved/broadcast exposure is not reviewable (#30)

The independent, non-authorizing native firewall intent now refuses
reserved IPv4 addresses such as Class-E `240.0.0.1` and limited
broadcast `255.255.255.255` as an HTTPS TCP listener target.
A canonical address string alone cannot make these meaningful
single-interface unicast exposure candidates.

The refusal occurs regardless of whether the operator has requested
firewall modification, so a disabled firewall toggle does not convert
an invalid host exposure into a safe candidate. Both Debian13 and
AlmaLinux10 fixture tests require static `FIREWALL_DOCUMENT_INVALID`,
no input mutation and preserved explicit unicast/port review semantics.

This guard covers the **firewall intent** boundary only. The separately
validated input contract, actual native bind, packet filter backend and
host-root authority must be rechecked by an eventual protected worker.
No real firewall rules, NGINX files or services are modified. Booted
systemd/SELinux acceptance remains NOT VERIFIED under #30/#19.

## Independent network listener exposure review (#30)

A disabled or absent `deployment.firewall.modify` means **only** "do not
modify existing firewall rules". It must **never** be interpreted as a
verified deny-by-default firewall or permission to expose NGINX on an
externally routable address. In particular, existing administrator rules
can already admit a listener bound to `0.0.0.0`, `::`, or a specific
non-loopback IP, without any firewall command by REPOCACHE.

The preview now provides two separate flags:
`firewall_change_review_required` means the operator explicitly
requested firewall modification on a non-loopback listener, whereas
`network_exposure_review_required` reflects the independent need to
review a *potential* non-loopback NGINX listener, **regardless** of the
firewall setting. Loopback-only `127.0.0.1` and `::1` produce false
for external listener review, but still require installed NGINX ownership
and explicit activation checks. `network_exposure_verified` remains
**false** for all cases, because these are configuration proposals, not
readings of kernel listeners or live firewall rules.

The existing public fields and statuses are unchanged. A new
cross-component regression suite compares the same validated
install-v1 document across firewall intent and rendered NGINX TLS
listener, checking the precise address/port, both protocol families,
opt-in/opt-out and no activation or firewall authorization. It runs
under both distro-native Python versions in the existing
`server-native-firewall-intent.yml` CI workflow. The test does not
open a socket, change a firewall or prove site policy; booted-host
network observation and operator consent remain mandatory Stage B
and original criterion #30-AC5.
