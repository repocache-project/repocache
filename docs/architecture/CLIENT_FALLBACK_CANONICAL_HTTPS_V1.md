# Canonical APT/DNF fallback HTTPS authority — issue #24

## Canonical HTTPS authority before native fallback proposal (#24)

The APT/DNF source compiler now compares the entire HTTPS authority with
its parsed, canonical host and decimal port spelling. `urlsplit.hostname`
normalizes uppercase DNS behind the caller's back; accepting the resulting
URI unchanged could preserve an ambiguous hostname in the native source.
Malformed DNS labels, trailing dots, legacy numeric-looking hostnames,
noncanonical IP spellings and port spellings such as `:0443` fail closed.
Canonical IPv4 loopback TLS fixtures remain usable in the disposable native
CI tests, but their presence is **not** route authorization and does not
make a production source write safe. The compiler still preserves existing
APT/DNF signing controls, requires exact upstream mapping and never edits
`/etc`; locked, signed native apply/fallback acceptance remains separate.
