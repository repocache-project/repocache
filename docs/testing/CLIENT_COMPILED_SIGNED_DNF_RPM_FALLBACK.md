# Compiler-generated DNF5 signed RPM fallback, disposable CI (#24)

## Integrated native acceptance path

The existing `ci_compiled_native_fallback.py dnf` workflow now uses the
same **real signed RPM and detached signed repomd.xml fixture** as the
independent DNF package-integrity regression. The actual
`client/native_fallback_plan.py` compiler generates the DNF5 source
proposal, preserving mandatory `gpgcheck=1`, `repo_gpgcheck=1`,
the pre-existing key path and the ordered cache/upstream base URLs.

With the repository under disposable HTTPS origins, the test invokes
stock AlmaLinux 10 DNF5 against the exact compiled configuration and
exercises four explicit availability transitions: preferred REPOCACHE
cache, unavailable cache with healthy upstream, recovered cache and both
endpoints unavailable. For every successful phase the native manager
downloads a synthetic RPM (without installing it), asserts identical
SHA-256 bytes and requires a positive signature verdict from RPM using
an **isolated temporary RPM database** containing only the ephemeral
fixture signing key.

The test also corrupts the RPM **after signed repository metadata is
created**, then requires native DNF5 to refuse the download despite
successful metadata handling. A separate wrong-CA case still proves TLS
certificate verification fails before either origin serves metadata.
No secret key, installed host RPMDB, production source or system package
is modified. The only test root-side writes are disposable key material
under a unique CI-specific path and transient package-manager state,
cleaned up after the run.

## Limits

This is stronger CI evidence for a *compiler-generated* native DNF
fallback than a hand-written DNF fixture, but it is **not** a production
client `repos sync --apply` implementation, protected lock/journal,
authorized #64 helper, trusted live server route approval, operator
consent, enterprise PKI test or booted AlmaLinux 10 SELinux acceptance.
Those original #24/#19/#31/#64 requirements stay **NOT VERIFIED**.
No signing, release publication, native host activation or unattended
source mutation is authorized by these test results.
