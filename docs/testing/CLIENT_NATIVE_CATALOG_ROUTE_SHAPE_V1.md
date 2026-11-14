# Native client catalog route shape — Stage A (#24)

The v0.6.0 server's authoritative public catalog is an active-only,
read-only projection of validated, installed NGINX routes. An older
read-only client may inspect historical same-origin catalog paths, but this
MUST NOT automatically authorize writing arbitrary same-origin URLs into
APT/DNF sources via a future \`repos sync --apply\`.

\`preview_native_client_catalog_route\` is a **pure, bounded, no-network**
future writer precondition. It requires a closed schema-1 mapping set with
unique HTTPS upstream/cache URLs, an exact approved client server origin,
the same repository ID grammar as install-v1, and the exact managed route
\`/__repocache/repos/ID/\`. It also denies duplicate origins/route IDs,
foreign ports, credential URLs, encoded dot traversal, unknown fields,
malformed data or missing targets. It never returns authenticated authority.

The existing network-fetching \`_catalog\` and the installed read-only
client \`check\`, \`repos list\`, and \`repos sync\` behavior are unchanged.
This function does not authenticate a server, bind observed live routing to
the catalog, obtain explicit administrator approval, validate signed
publisher identity or inspect/modify files. The installed client continues
to refuse \`repos sync --apply\`.

**Still required** for issue #24: a trusted installed issuer/owner manifest,
live active-only catalog exposure, UC-45 administrator route consent, a
root-owned helper, held native APT/DNF locks, validated package-manager
fallback/signature policy, durable multi-file rollback and native booted
Debian13/Alma10 (including SELinux enforcing) acceptance. Passing this
pure route-shape check can never close the issue or authorize a source write.
