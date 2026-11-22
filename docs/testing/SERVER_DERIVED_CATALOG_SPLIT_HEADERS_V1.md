# #95 — split NGINX header security for active-only catalog previews


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
