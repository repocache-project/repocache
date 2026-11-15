# Configuration-only repository additions with native signed metadata

**Milestone:** v0.6.0 · **Primary issue:** #95 · **Dependencies:**
#18/#27/#28/#29/#31/#64 and final native #19.

This Stage-A integration is the first bounded native package-manager integrity
check over a newly **configuration-only** APT or DNF repository mapping in the
existing REPOCACHE-generated NGINX cache. Previous NGINX MISS/HIT fixtures
were metadata-*shaped* but did not prove the native package managers accept
cryptographically authenticated package metadata delivered via this route.

## Test-only chain

The job uses a fresh Debian 13 or AlmaLinux 10 Docker container, with a
read-only bind-mounted checkout. Package tools and NGINX installed in the
container are stock distribution packages. The Python test refuses ordinary
host execution and requires the explicit disposable Docker intent marker.

1. Build a synthetic APT repository with a real, ephemeral Ed25519-signed
   `InRelease`, SHA-256-specified `Packages` index and a harmless .deb
   fixture, or a DNF repository with real ephemeral signed `repomd.xml`,
   a no-script/noarch RPM, independently verified private RPMDB signature.
   Both fixtures and private signing keys exist **only** in the short-lived
   container; never use or advertise the REPOCACHE release publisher key.
2. Replace the example repository metadata *as configuration*, not source:
   select one new custom ID, enable the corresponding approved APT/DNF
   layout, set a fixed HTTPS upstream base URL, validate a public IP pin,
   render a REPOCACHE NGINX cache fragment and explicitly assert there is no
   activation/catalog authority.
3. In the **test-only** NGINX configuration, remap exactly the validated
   public-pin server line to a separate loopback TLS origin. Preserve generated
   HTTPS, SNI, source/path restrictions and cache behavior; NGINX runs with a
   distribution-owned worker and disposable cache directories.
4. Run a native `apt-get update` followed by `apt-get download` or DNF
   signed metadata refresh followed by download-only, using exclusively
   temporary package-manager sources, caches, CA trust and the ephemeral
   repository signature key. Native signed metadata verification and package
   SHA-256 (and the separate RPM signature) must PASS. No package is installed.
5. Request the signed metadata and original package over the generated HTTPS
   repository URL twice, prove the *second* native NGINX response is HIT and
   byte-identical to the signed fixture, and prove actual upstream contact.
   The APT case also refuses a wrong-CA native package-manager refresh.
6. Terminate the private NGINX process and local TLS origin; the CI container
   and all keys, sources, package caches and artefacts are destroyed.

Both matrix jobs must complete SUCCESS, alongside project Python/security CI
and the nine strict required checks on the exact tested HEAD.

## Not claimed

Ephemeral CI signing is **not** publisher-key signing, production APT/DNF
repository trust or a real installed root key. This is not a live systemd
NGINX service, SELinux enforcing, an authorized repository lifecycle writer,
an all-time stable ID ledger, a published client catalog, a real authorized
force-cleanup path or a signed deployed artifact. The generated NGINX
configuration is applied **only** by an expressly isolated disposable
test process after `nginx -t`; the actual source code does not expose any
write/reload authority.

Existing standalone native APT/DNF signed transport tests cover tampered
metadata/package negatives; this test adds the *missing generated NGINX
route in the signed chain*. Do not infer that production catalog/NGINX
atomic activation or full issue #95 AC1–AC7 has passed before #31/#64
and the final booted Debian 13 / AlmaLinux 10 campaign in #19.
