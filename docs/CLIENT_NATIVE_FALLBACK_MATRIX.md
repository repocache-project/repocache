# Native client metadata-fallback experimental test matrix

**Status:** executable CI experiment, not production acceptance and not a
complete failover proof.  
**Tracking:** [#24](https://github.com/teixemf/repocache/issues/24),
UC-02/UC-16/UC-34/UC-35.  
**Targets:** Debian 13 `debian:trixie-slim` and AlmaLinux 10
`almalinux:10`.  
**Entrypoints:**
[probe script](../scripts/ci_client_native_fallback.py),
[GitHub Actions workflow](../.github/workflows/client-native-fallback.yml).

## Why these tests exist

The Debian APT mirror transport supports local `mirror+file:` lists and
`priority:N` metadata. It explicitly says that mirrors **without** a priority
may be selected at random. A literal cache URL followed by an upstream URL,
without priorities, is therefore insufficient evidence that the cache is
preferred. See
[apt-transport-mirror(1), Debian 13](https://manpages.debian.org/trixie/apt/apt-transport-mirror.1.en.html).

DNF documents `baseurl` as an ordered list of URLs, but this is not a
guarantee for each failure mode or each repository configuration. See
[DNF5 configuration reference](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html).

## Test fixtures and trust boundaries

The workflow prepares dependencies inside **disposable containers**, then
starts two loopback HTTP endpoints hosting the same intentionally synthetic
repository. One endpoint acts as REPOCACHE, the other as the upstream.
The tests operate on private source files, metadata caches and trust files in
a temporary directory. They do **not** mutate host APT/DNF repository sources.

- For APT, an ephemeral OpenPGP key signs an isolated `InRelease`. A
  dedicated `Signed-By` keyring verifies metadata without weakening the
  system's repository-signature configuration or globally installing trust.
- For DNF, `createrepo_c` generates metadata for an empty repository.
  `gpgcheck=1` remains set. The test does not install any RPM and metadata
  signatures are not tested, so **DNF package/metadata authentication is
  NOT VERIFIED** by this experiment.
- Both probes use **HTTP loopback only**. They therefore do not test
  external HTTPS certificate validation, private CAs, DNS failure,
  redirects, metadata tampering, package download or interrupted writes.
- Each operation uses a fresh metadata cache and records per-backend
  request counts; a successful exit without requests to the expected backend
  is *not* sufficient to pass.

## Executed scenarios

| Scenario | Primary cache | Upstream | Expected observation |
| --- | --- | --- | --- |
| Preferred cache | Healthy | Healthy | Native metadata update succeeds; requests primary, not upstream |
| Primary outage | HTTP 503 | Healthy | Native metadata update succeeds; requests both primary and upstream |
| Cache recovery | Healthy again | Healthy | A subsequent fresh metadata update selects primary again |
| Complete outage | HTTP 503 | HTTP 503 | Native metadata update fails; both sources have been attempted |

No scenario removes package signatures or claims source rewrite capability.

## Remaining mandatory acceptance gates

**NOT VERIFIED** until separate targeted tests PASS:

- Production-like **HTTPS** with certificate errors, timeouts, 404, 5xx,
  DNS failure, redirects and CA/private-CA paths, without weakening TLS.
- Signed Debian metadata and authentic signed RPM package downloads
  through both cache and upstream, including mismatch and tampering failure.
- Real package-manager behavior with authentic Debian 13 and AlmaLinux 10
  repository formats, `mirrorlist`, `metalink`, multiple suites, components,
  architectures, and mixed external distributions.
- Clean booted systems with systemd, AlmaLinux SELinux, OS package-manager
  locks, root/non-root privilege enforcement and real protected source paths.
- REPOCACHE client transactional write/rollback, reboot/power-loss recovery,
  drift detection, original-source preservation and uninstall preparation.

If any native metadata probe fails, the result is a **FAIL** of this exact
tested combination; do not silently downgrade it to a warning or fall back
to an unsigned repository. Keep `repos sync --apply` disabled under the
UC-16 fallback gate until the supported combinations have passed real tests.


## Added HTTPS loopback metadata verification (exact-source CI)

The same two native container jobs also run the identical preference, outage,
recovery and complete-outage scenarios over private HTTPS loopback endpoints,
rather than treating HTTP-only probes as sufficient. The isolated workflow
generates a short-lived self-signed TLS identity with an IP subjectAltName
for 127.0.0.1, pins its certificate through APT Acquire::https::CaInfo or
DNF sslcacert, and explicitly keeps TLS peer/hostname verification enabled
alongside the existing package-signature settings.

A fifth HTTPS-only wrong-CA scenario pins a different, untrusted test
certificate for the client while the servers remain healthy. The package
manager must reject the metadata request without issuing HTTP requests to
either backend. A failure or an unintended TLS downgrade fails CI.

These tests exercise **TLS certificate trust and loopback metadata routing**
only: generated self-signed certificates are never publisher or production
trust anchors; they do not establish real CA chains, DNS, real public HTTPS
origins, package downloads, label preservation, or host APT/DNF configuration
safety. DNF repo metadata signing and actual signed RPM transactions remain
NOT VERIFIED; a metadata-probe PASS must not enable --apply.

## Signed DNF metadata refusal in disposable containers

The AlmaLinux 10 native fallback job additionally runs a private HTTPS
metadata probe with repo_gpgcheck=1 and a unique ephemeral OpenPGP key.
createrepo_c produces an empty test repository; the probe signs repomd.xml
with a detached ASCII signature and pins the corresponding public key
through the isolated DNF gpgkey setting. The package-manager commands
are noninteractive; no real system repository file is modified.

Preference, upstream outage, recovery and total outage must still behave
as expected when metadata signatures are required. A separate fixture
deliberately replaces the detached signature and requires DNF makecache
to fail, rather than silently accepting unsigned metadata or TLS bypass.
Wrong-CA refusal continues to run in the same signed-metadata mode.

These keys and metadata are synthetic and do not authenticate actual
publisher metadata or RPM package payloads; no RPM install is attempted.
Real signed RPM package transactions, production server catalogs and
native host SELinux/systemd tests remain NOT VERIFIED. This test may
not be used as permission to enable repos sync --apply.

## Isolated APT package download with signed metadata and file integrity

The Debian 13 native HTTPS job now additionally builds a disposable
architecture-independent .deb without maintainer scripts and indexes its
SHA-256 and size in Packages, Packages.gz and Packages.xz. A temporary
OpenPGP key signs the Release metadata. In private APT lists and cache
directories, apt-get update then apt-get download must retrieve the .deb
via cache preference, upstream outage fallback and cache recovery.
The probe verifies the exact SHA-256 of each downloaded .deb against the
original locally generated archive; it never executes dpkg --install.

A tampered-package scenario changes the served .deb bytes AFTER the
Release/Packages hashes have been signed. APT must reject that transfer;
success or a downloaded package with the wrong SHA-256 fails the job.
TLS wrong-CA, total outage and earlier metadata checks still fail closed.

These are disposable unsigned payloads authenticated by synthetic signed
APT repository metadata, not genuine publisher packages, and do not prove
production server catalogs, real network sources or native-host operation.
