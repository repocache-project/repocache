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
