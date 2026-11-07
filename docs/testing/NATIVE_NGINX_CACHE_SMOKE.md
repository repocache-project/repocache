# Disposable native NGINX cache/TLS smoke — #28 / #27

This test executes real distribution-packaged NGINX on **Debian 13**
and **AlmaLinux 10** as a non-root process in disposable Docker containers.
The workflow installs native nginx, Python, OpenSSL and CA certificates
from the OS repositories, then runs with no external network, a read-only
root/checkout, dropped capabilities, and a temporary TLS key which never
leaves the container.

The independent test validates generated #28 APT/DNF **candidate** fragments
using real `nginx -t`, with synthetic PUBLIC pinned addresses; this
never activates a route or publishes discovery. Production origin-pinning
continues to reject loopback/private addresses.

A separate **test-only local** NGINX TLS proxy/cache configuration
connects to a loopback HTTP fixture. Real HTTPS requests verify a trusted
short-lived certificate, exact bytes for two APT objects and two DNF objects,
and an observed MISS followed by HIT with one backend fetch/object. It
also checks unapproved route refusal, non-GET denial, ignored upstream
X-Accel-Redirect and rejection of upstream 3xx redirects. No real package
manager, signed repository metadata or production endpoint is contacted.

A checked-in script **is not execution evidence**. Exact-HEAD GitHub Actions
job logs for both platforms are required to claim scoped PASS.

The original complete-server acceptance remains **NOT VERIFIED**: actual
administrator-authorized routing/catalog, real signed upstream APT/DNF
transfer through a managed route, native package transaction, booted
systemd and enforcing SELinux, external service/TLS, cache ownership and
capacity, staged reload/rollback and host preservation. No privileged
production operations, GitHub releases or publication are performed.
