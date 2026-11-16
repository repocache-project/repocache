# Canonical REPOCACHE client server HTTPS origin — #24

The noninteractive client accepts either an explicit operator `--server`
origin or an independently pinned, read-only root-owned installed config.
The v0.6.0 client already promises a canonical HTTPS origin (without query,
userinfo, fragment, percent-encoded name or path). The parser now validates
the **original authority text** against its decoded DNS/IP host and decimal
port rather than trusting `urlsplit().hostname`'s lossy normalization.
Uppercase hosts, padded ports and noncanonical IPv6 spellings are refused;
the approved lowercase DNS, canonical IPv4/IPv6 and decimal port forms remain.

This reduces ambiguity between the intended operator-provided TLS/catalog
origin and a normalized origin used later for identity checks. No fallback
source or server is rewritten; the explicit `repos sync --apply` command
remains gated behind the authenticated, root-owned transaction, signed
catalog and booted Debian 13 / AlmaLinux 10 acceptance work. Do not infer
that a canonical string alone authenticates its DNS, TLS CA, or service.
