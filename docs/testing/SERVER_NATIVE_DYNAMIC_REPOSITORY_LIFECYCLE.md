# Native data-driven repository add/remove smoke (#95/#28/#29)

## CI-exercised scenario

The existing **Disposable stock NGINX HTTPS cache smoke** now exercises an additional,
previously unknown APT repository and then an additional DNF repository, using only validated install-v1 metadata and
a deterministic non-authoritative automatic ID. It uses the packaged NGINX
binary on disposable, rootless Debian 13 and AlmaLinux 10 runners; no
repository-specific production source edits are necessary to generate the
additional routes, isolated cache zones or inert derived client catalogs.

The test performs the complete **Stage-A test-only data-plane sequence**:

1. Begin with active APT and DNF routes, real trusted fixture HTTPS upstreams
   and confirmed warm cache HITs.
2. Construct a supported new APT repository from an existing validated
   schema object but with a distinct HTTPS origin path; omit the administrator
   ID. Require deterministic `propose_automatic_repository_id`, distinct
   output and repeat/no-op planning with a frozen all-time reservation view.
3. For each newly added APT **and** DNF repository in turn, re-render the
   actual multi-repository NGINX fragments with three isolated cache zones,
   validate the public-IP candidate through stock `nginx -T`, and derive
   a three-entry, still inert client catalog containing the new route.
4. In the **test-only** NGINX process, replace the prevalidated public IPs
   with an isolated local HTTPS fixture address, run stock `nginx -t` and
   execute an explicit test-only master reload. Wait until former workers
   drain. Assert real new APT `InRelease` and new DNF `repomd.xml` metadata
   each yield **MISS then HIT** with exactly one independent upstream request,
   while both existing APT and DNF routes remain HIT.
5. Build a pure normal removal intent; restore the exact original NGINX
   bytes through another validated test-only reload. Assert new route 404,
   preservation of all newly cached file bytes and inode identifiers, old
   APT/DNF HIT and continued NGINX health. A caller-provided tombstone set
   prevents the automatic allocator from proposing either removed ID again.

Both the original and new candidates explicitly deny activation, state
commit and catalog publication. The ID reservation set used here is fixture
data, **not** an authenticated durable all-time ID ledger. Neither
`nginx -t`, test-only reload, discovery projection nor a successful
real TLS request confers privileged operator authority or authorizes a
production deployment.

## Evidence boundary

This closes a **specific Stage-A data-plane test gap**; it does not by itself
close the parent #95 acceptance. Real booted Debian 13 and AlmaLinux 10
systemd/SELinux behaviour, validated root-owned state-v2 transaction lock,
crash-safe atomically published catalog, authenticated administrator intent,
trusted upstream DNS, publisher signing, real package-manager integrity,
client fallback and production NGINX activation remain **NOT VERIFIED**.
A source-level mock of a ledger must never substitute for a protected
native writer. No production cache or client source is altered by CI.
