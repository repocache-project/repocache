# Bounded DNS child identity for native v0.6 transactions (#28 / #31)

The existing DNS pin resolver launches one fixed, short-lived Python child
with an OS-enforced timeout. The root-owned v0.6 native transaction must
not perform unbounded \`socket.getaddrinfo\` under its own privileged process
or delegate an unbounded root-credentialed DNS child.

\`bounded_getaddrinfo\` now accepts an optional **paired** internal numeric
\`run_as_uid\` and \`run_as_gid\` for future native callers. A privileged
caller can only request a **nonzero** UID/GID, with all supplementary groups
cleared, closed descriptors, sanitized environment, fixed executable/inline
code, no shell, no inherited stdin and bounded output/time. If either
identity is absent/malformed or the caller is not root, it refuses before
the child is started. Ordinary unprivileged candidate refreshes still use
their existing default arguments and behavior.

Real Linux container tests check the child reports UID 65534, GID 65534
and no supplementary groups while the parent remains UID 0. Additional
negative tests reject root targets, booleans, out-of-range IDs, mismatched
UID/GID inputs and nonroot callers. This is a **privilege-reduction tool**,
not a trusted DNS response: the independent destination policy must still
reject private, link-local, multicast and special-purpose IPs.

The future #31 native root transaction must obtain the approved service
UID/GID from trusted installed identity, enforce a total bounded DNS
refresh cycle, and revalidate every resolved address before staging NGINX.
This PR does **not** install the root worker, change current production
resolution, authenticate DNSSEC, publish a route or authorize any NGINX
reload. Final booted Debian13/AlmaLinux10 systemd/SELinux and #64 security
review remain NOT VERIFIED.


## Root caller without an explicit credential drop is now refused

Previously, the paired nonroot UID/GID was optional even if the caller was
UID 0. An inadvertent call from a future privileged native transaction
could therefore spawn a fixed, bounded Python resolver with **root
credentials**. The candidate resolver now refuses this case **before**
creating any process, returning the static `DNS worker: unprivileged
identity required` error.

Unprivileged callers retain the original no-extra-identity API, while
root callers must explicitly provide both a nonzero UID and GID. In both
cases the resolver still uses its fixed isolated program, sanitized
environment, no shell, closed descriptors and timeout. Native kernel
tests of the explicit UID/GID drop are preserved; mocked subprocess
tests now explicitly model a nonroot caller, and a genuine root execution
with no drop is never performed by the test suite.

This change enforces a **negative privilege boundary only**. It does not
choose an installed service account, authenticate a caller/response,
install a scheduler, or authorize NGINX/catalog activation. The future
#31 installed transaction still requires a trusted dedicated identity
under the protected state lock, and final #19 native systemd/SELinux
acceptance remains NOT VERIFIED.
