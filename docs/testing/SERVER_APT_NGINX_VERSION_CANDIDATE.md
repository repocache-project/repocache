# Bound native Debian APT candidate to the nginx package (#27)

A successful signed APT metadata refresh alone does not prove the
`apt-cache policy nginx` response contains an installable NGINX candidate.
The former parser accepted any single line starting with `Candidate:`,
even without the expected queried package header, and did not validate
whether the candidate was a Debian version rather than an arbitrary string.

The read-only signed-metadata probe now requires the first nonempty
policy line to identify the fixed `nginx:` package, exactly one nginx
header and one candidate with Debian's bounded version-token syntax,
including optional numeric epochs, `~` pre-release and `+deb13`
updates. Absent, forged, duplicated, malformed or untrusted candidate
output returns `NATIVE_PACKAGE_NOT_AVAILABLE`. Existing exact native
APT signed keyring and metadata options remain mandatory.

Negative tests cover foreign package headers, path-like candidate data,
malformed token syntax, missing header and duplicate headers/candidates;
positive tests preserve standard and epoch/backport Debian versions.
The fixed DNF trust and available query remain unchanged.

The probe is evidence for Stage-A availability only; it never performs
package installation, accepts release owner signatures, invokes systemd,
authorizes protected native writes or proves booted Debian 13 readiness.
The wider #27/#19 original release gates remain NOT VERIFIED.
