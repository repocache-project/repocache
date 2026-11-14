# Composed native HTTPS repository server candidate (#28 / #30)

The deterministic \`render_repository_https_server_candidate\` function
joins the **existing** validated native NGINX TLS listener and per-repository
upstream/cache renderers using the exact same v1 document and expected state
generation. The result supplies an \`http_context_fragment\` and one complete
\`server_block_fragment\` for the appropriate stock NGINX \`http{}\` context.

It never reads TLS certificate/key bytes, queries DNS, writes files, invokes
NGINX, changes the firewall, grants an operator role or publishes any client
discovery catalog. Desired-active repositories without an exact approved pin
candidate are rejected rather than partly exposed; disabled IDs generate no
cache zone or route. It cannot become a default virtual host or open proxy.

The native TLS CI test now creates a disposable, unprivileged, short-lived
certificate and key, composes one real candidate for APT and DNF paths, and
runs \`nginx -t\` and a real HTTPS handshake using stock NGINX on Debian 13
and AlmaLinux 10 containers. This verifies candidate syntax and HTTP/TLS
isolation **only in disposable userspace**; no signed package metadata is
fetched through the composed candidate. Its helper health location is
CI-only and is not part of production output.

**Still required before production:** authenticate operator and host-root
authority, package ownership and SELinux labels; own the exact managed
include and cache directories; verify genuine certificate chain, private-key
access and supported NGINX binary; perform durable #31 state/NGINX/catalog
journal with validation, reload and known-good rollback through reviewed
#64 privileged control; verify active exposure before publishing the derived
catalog; complete native booted #19 campaign. None of those criteria can be
inferred from a successful pure renderer or green container CI.
