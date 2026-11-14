# Stock NGINX package owner observation (v0.6.0 Stage A)

**Primary issue #27.** This narrow, read-only capability verifies that
the fixed /usr/sbin/nginx binary corresponds to the expected *payload-owning* operating
system package name (Debian `nginx`; AlmaLinux `nginx-core`, which the
native `nginx` metapackage installs) on Debian 13 and AlmaLinux 10. It improves early
detection of a foreign installation before future server provisioning.

The probe accepts only the two versioned platform identities, the fixed
binary path, root-owned regular executable metadata without group/world
writes or multiple hard links, and an exact package-owner name from the
native package database. It takes the binary inode/stat identity before
and after the fixed, timeout-bounded dpkg-query or rpm call. It rejects
foreign package ownership, replacement, malformed output and all
unsupported systems with static redacted errors. No user-controlled
path, package name, shell or active service is involved.

The dedicated CI matrix installs official native NGINX packages on both
supported distro containers and runs real package database queries plus
negative/security tests. The probe never invokes apt/dnf install, changes
package manager state, signals a service, reads private keys, or writes
NGINX configuration.

**Limits:** a local package database can be modified or compromised; a
positive owner match is not evidence of package signature or provenance,
genuine installed host-root identity, trusted package sources, exact
NGINX unit ownership or running systemd/SELinux. These remain false
explicitly in the JSON report. A privileged installer must independently
recheck signed package metadata/payload, binary and service identity under
its authenticated protected transaction lock.

No real host provisioning or service activation is approved here.
Original issue #27's clean booted native Debian/AlmaLinux tests, rollback
and incompatible-NGINX non-adoption remain NOT VERIFIED through issue #19.
