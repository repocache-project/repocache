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
