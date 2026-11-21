# Native active-only NGINX and derived discovery withdrawal

**Primary issue #95, coordinating #28, release v0.6.0.**

The server cannot advertise a repository after it becomes disabled.
This CI integration checks the actual approved repository renderer and
the automatically derived read-only client catalog against real stock
Debian 13 and AlmaLinux 10 NGINX parser output. It uses three successive
candidate states: two repositories active, one disabled, then both
re-enabled. The production renderer first validates public upstream
pins, source layout and policy; NGINX -T parses the full candidate.

In the disabled phase the removed route and catalog mapping must both
disappear. A forged parser dump containing the disabled route is refused
by the existing catalog candidate validator. A private cached-object
sentinel keeps the same inode and SHA-256 across all three candidates,
demonstrating that route withdrawal never requires deletion.

The test drops to UID/GID 65534 inside disposable distro containers.
Every configuration, scratch cache and temporary file remains private;
no NGINX service is started or reloaded, and no upstream is contacted.
A positive nginx -T result is not proof of the actual installed route
configuration, trusted request approval or published client discovery.

Still NOT VERIFIED: live NGINX route withdrawal/activation, installed
root worker and atomic WAL, true NGINX cache-loader reuse, native
systemd/SELinux on booted Debian 13 and AlmaLinux 10, and signed
APT/DNF client fallback. Original #95 and native acceptance #19 remain
open; this candidate CI provides no production authority.

## Split NGINX header refusal before catalog preview (#95)

NGINX accepts line breaks between directive tokens. A source-controlled
read-only catalog preview must not parse only the single-line
`location ^~ /__repocache/repos/ID/` grammar and silently overlook an
unmanaged `location` or `upstream` whose keyword and arguments are
separated by a newline. Any such split header is now conservatively
rejected, even for an unrelated NGINX location: no installed ownership
adoption, ambiguous route shadowing or discovery publication is inferred.
Comments that only describe split directives remain inert.

The ordinary and the stronger exact-HTTPS derived-catalog previews
share this refusal. Both still process **untrusted** supplied `nginx -T`
text and exit codes, never an authenticated live listener. In CI,
`tests/test_server_derived_catalog_candidate_v1.py` exercises
inactive-route shadowing, foreign pinned upstreams and safe commented
text; the existing Debian 13/AlmaLinux 10 native `nginx -T` checks remain
independently necessary. A verified protected NGINX master, an
administrator-authorized generation and an atomic published catalog
remain NOT VERIFIED pending #31/#64/#28 and #19 host acceptance.
