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
