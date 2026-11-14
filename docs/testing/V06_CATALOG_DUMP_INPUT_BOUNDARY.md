# Strict bounded NGINX -T catalog candidate input (#95 / #28)

`preview_derived_catalog_from_nginx_dump` accepts caller-supplied,
**untrusted** NGINX configuration text, not authenticated runtime evidence.
The source-only catalog preview now refuses raw Python strings longer than
4 MiB **before** UTF-8 allocation, checks the actual strict encoded byte
length, and rejects lone Unicode surrogates rather than preserving them
through `surrogatepass`.

The existing exact deterministic active-route and upstream-set matching
remains unchanged. Legitimate UTF-8 comments are still accepted. The result
continues to report false for every installed-host, NGINX runtime and catalog
publication authorization field.

This bounded code is never a replacement for the final #19 native
Debian/AlmaLinux systemd/SELinux, live-route and signed-cache acceptance.
