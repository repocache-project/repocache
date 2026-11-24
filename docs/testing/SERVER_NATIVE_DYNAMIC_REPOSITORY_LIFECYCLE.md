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

## Native booted malformed-candidate refusal and cache retention (#28)

The existing `scripts/ci_v06_vm_nginx_cache_guest.py` P0-2 scenario,
running as an unprivileged account in the **actual booted** Debian 13 or
AlmaLinux 10 QEMU guest (SELinux Enforcing on AlmaLinux), now exercises a
real packaged NGINX failure-and-restore sequence **after warming both APT
and DNF metadata/package fixtures**:

1. Snapshot the exact private NGINX configuration bytes, and stage a
   deliberately invalid directive in that same disposable file.
2. Require the real packaged `nginx -t` to **reject** it before sending a
   reload. Verify the pre-existing NGINX master stays alive and all four
   previously warmed APT/DNF metadata/package URLs still return correct
   bytes and `HIT`, without an extra upstream request.
3. Restore only the saved private fixture bytes, require `nginx -t` to
   pass and perform a **genuine test-only NGINX reload**. Verify that
   every object remains a `HIT` with original bytes and upstream counts.
4. Verify the original vendor systemd `nginx.service` remains inactive
   throughout; never modify `/etc/nginx`, host trust anchors, APT/DNF
   sources, publisher keys, firewall rules or production catalog files.

The conservative evidence collector adds the narrow `28.04`
**EXERCISED_PARTIAL** coverage only when a complete exact-SHA booted
QEMU smoke includes both the existing APT/DNF HIT marker and the new
syntax/refusal/restoration marker. An absent marker, changed SHA or failed
guest is **NOT VERIFIED**, not acceptance PASS.

This does **not** prove the installed #31/#64 root worker blocked an
unapproved production reload, did an atomic multi-resource catalog
rollback, verified authentic APT/DNF metadata signatures or recovered an
interrupted privileged transaction. Full #28 and #95 acceptance remains
OPEN until the installed signed-fixture native path and actual published
active-only catalog are exercised with corresponding provenance and
real native OS evidence; publisher-owned signatures are separate Stage C.
