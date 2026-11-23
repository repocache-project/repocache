# Stock NGINX multi-repository HTTPS evidence (#28)

The existing `render_repository_nginx_bundle_candidate` and
`render_repository_https_server_candidate` in
`server_nginx_repository_bundle_v1.py` already implement strict, inert
multi-repository candidate assembly. **Do not introduce a second renderer.**

This increment adds a focused regression for the existing complete HTTPS
server composer and runs both that regression and the existing multi-repository
suite with stock, distribution-packaged NGINX on **Debian 13** and
**AlmaLinux 10** in disposable CI containers via
`server-nginx-pins-native.yml`. The additional test composes active APT and
DNF upstreams with separate pin sets and cache zones, generates a disposable
self-signed test certificate, checks the complete NGINX HTTPS configuration
with the *actual* `nginx -t` parser, and refuses unsafe or disabled routes.
The test never starts/reloads a system-managed service, uses external network
destinations, or modifies production paths. No actual upstream fetch occurs.

The generated output is **not** proof of operator approval, authenticated
DNS inputs, trusted state generation or root-owned NGINX include, live TLS
hostname trust, successful reload, cache HIT, or atomic catalog publication.
All authority and live-host evidence fields remain false. Installation
and activation require independent #31/#64 transaction protections; #19
collects final booted Debian 13 and enforcing AlmaLinux 10 acceptance.
Stock NGINX container syntax is useful Stage-A evidence, never a substitute
for those mandatory host/rollback/security checks.

Run locally with `pytest -q tests/test_server_nginx_repository_bundle_v1.py
tests/test_server_nginx_https_bundle_native_v1.py`. The `nginx -t`
positive case skips unless stock NGINX and OpenSSL are installed.
