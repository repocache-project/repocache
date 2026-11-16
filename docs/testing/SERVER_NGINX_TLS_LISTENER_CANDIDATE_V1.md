# HTTPS listener from the validated v0.6 server contract (#30)

The existing install-v1 schema allows operator-provided certificate/key paths,
a canonical listening IP and hostname/port. This module constructs a fixed
stock NGINX HTTPS server-context fragment with TLS >=1.2, session tickets
disabled and no server version header. IPv6 listen addresses are bracketed.
Certificate/key paths are additionally limited to NGINX-safe single tokens,
rather than trusting the more permissive general install-document path
validator; no injected semicolon, whitespace, variable or comment survives.
No new TLS architecture, ACME account, key material or public firewall
exception is introduced.

An independent native CI test replaces the *references only in a private
synthetic fixture*, executes a real distro NGINX HTTPS handshake, verifies
the exact requested hostname and rejection of an incorrect hostname or
untrusted signer. The source renderer never opens key bytes, validates
actual operator key provenance, changes a firewall, creates a listener or
reloads NGINX. This result remains a non-activating candidate.

A reviewed authorized installer must independently pin actual root-owned
certificate/key inodes, validate permissions/SELinux, operator hostname
authority and existing service ownership, run nginx -t with the full
managed configuration, retain the old generation on failure and exercise
the final booted Debian13/Alma10 hosts. These are #30/#31/#64/#19
NOT VERIFIED and are not waived by this Stage-A fragment.


## HTTP authority isolation on a valid TLS session (#30)

The non-authorizing stock NGINX listener candidate rejects a request whose
normalized HTTP Host (or HTTP/2 authority) differs from the single validated
deployment hostname. A correctly authenticated TLS certificate and SNI
do not by themselves authenticate the subsequent HTTP Host value, especially
where the listener might otherwise become a default virtual host.

The candidate now emits a fixed server-context comparison of NGINX `$host`
against the already validated canonical ASCII DNS name, returning HTTP 421
before any managed cache location is evaluated. This is *not* a hostname
mapping, redirect, runtime name resolver, operator approval or firewall grant.

The Debian 13 and AlmaLinux 10 disposable native listener CI obtains an actual
trusted TLS connection using the canonical SNI, then sends an unrelated Host
header and requires a 421 response with no protected test payload. Existing
positive HTTPS negotiation, hostname/certificate refusal, untrusted CA, and
HTTP downgrade tests are preserved.

**Limits:** this is only a generated inert candidate and disposable NGINX
userspace smoke. Production certificate/host ownership, root-controlled
configuration, activation, actual DNS and SELinux/systemd remain NOT VERIFIED.
The future full server integration must also verify that *every* active
listener and virtual host uses the same fail-closed routing boundary.

## Required wire authority, not NGINX fallback hostname

The earlier candidate compared the NGINX \`$host\` variable. A real disposable
NGINX reproduction showed a critical difference: for HTTP/1.0 without a
Host header, \`$host\` falls back to \`server_name\` and the protected
endpoint was served with **200**, despite the intended authority boundary.

The candidate now checks the actual \`$http_host\` value with an anchored,
case-insensitive regular expression built from the escaped validated DNS
name. It allows only that hostname and, optionally, the **exact configured
HTTPS port**. A missing Host, a foreign name, or a foreign port returns
HTTP **421** before repository locations execute. IPv4/IPv6 listener binds
and genuine TLS SNI remain independently validated. Disposable stock
NGINX on Debian 13 and AlmaLinux 10 exercises no-Host HTTP/1.0, mismatched
ports and canonical Host with explicit port. No host activation authority
is inferred from this candidate or test.


### Absolute-form HTTP request-target authority

A second disposable stock NGINX reproduction demonstrated that
`GET https://foreign.example.invalid/... HTTP/1.1` with the *approved*
Host header reached the protected NGINX route (HTTP 200) when only
`$http_host` was checked. This is because NGINX `$host` takes authority
from an absolute-form request target in preference to the Host field.

The candidate therefore retains **two complementary guards**:
`$http_host` enforces a supplied approved Host and optional exact port,
and `$host` rejects a divergent absolute-form request-target authority.
Real Debian 13/AlmaLinux 10 native NGINX tests include the foreign
absolute URL under valid TLS SNI and canonical Host, requiring HTTP 421
with no protected payload. Neither guard is an authorization to
install/reload NGINX or publish the catalog.

## Explicit IPv6-only listeners (#30)

For an administrator-selected IPv6 bind, the deterministic NGINX listener
candidate now appends `ipv6only=on` to its IPv6 `listen [address]:port ssl`
directive. This guards the otherwise platform-dependent possibility that a
wildcard IPv6 socket also receives IPv4 connections. IPv4 listener candidates
are unchanged, and selecting two address families still requires explicit
administrator intent, owned firewall state and native listener checks.

Unit regressions cover IPv6 loopback and wildcard and preserve the IPv4
normal/wildcard contract. The non-activating source renderer never opens a
socket or modifies the host; live dual-stack/SELinux/firewall verification
on Debian 13 and AlmaLinux 10 remains NOT VERIFIED until installed #30/#19
acceptance. Native userland TLS smoke continues testing IPv4.

The combined HTTPS candidate also retains the separately tested exact TLS SNI,
raw HTTP Host, and absolute request-target gates (#347/#346). A guarded
IPv6-only socket cannot bypass authority validation, and neither this render
nor a rootless fixture establishes native host/firewall exposure.

## Real rootless IPv6-only socket verification (#30)

The two-distro GitHub Actions workflow
`server-tls-ipv6-only-native.yml` installs stock NGINX in disposable,
offline, rootless, read-only distro containers and launches an isolated
generated `listen [::]:18445 ssl ipv6only=on` candidate using a synthetic
one-day certificate. The test requires actual IPv6 loopback support, checks
stock `nginx -t`, performs a trusted TLS handshake to `::1`, and verifies
that a direct IPv4 TCP connection to `127.0.0.1` on the **same port** is
refused. It also tests absent or foreign TLS SNI and foreign HTTP Host
over IPv6; HTTP 421 must contain no protected test payload.

Unavailable IPv6 is a CI failure, not silently counted as PASS. The
namespace exposes no host port and cannot write production TLS material.
These results show real packaged NGINX socket behavior inside CI, **not**
installed booted Debian/AlmaLinux hosts, AlmaLinux SELinux enforcing,
trusted production key custody, an operator-approved firewall or an
authorized REPOCACHE service activation. Those remain NOT VERIFIED.
