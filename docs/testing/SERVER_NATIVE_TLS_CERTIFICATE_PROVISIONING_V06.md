# v0.6.0 — operator-provided TLS certificate preparation (#30)

**Status:** source-controlled operator procedure, **not** a certificate
issuer, an installed privileged service, a security certification or a
successful native-host acceptance result. Follow this only on a clean,
snapshot-backed Debian 13 or AlmaLinux 10 (x86_64) evaluation host after
independently authenticating the exact source and candidate. No private
key material is part of REPOCACHE source, GitHub Actions or a release
archive. The read-only procedures here do **not** create keys, alter
NGINX, reload services or open firewall ports.

## Choose and verify the trust path

1. Use an independently authenticated enterprise/internal PKI, trusted
   public CA, or separately controlled offline CA. An offline host does
   **not** require ACME issuance. If an online CA workflow is needed,
   perform it under the operator's own provisioning process: REPOCACHE
   does not invoke ACME or obtain/renew certificates on the host.
2. Provision a certificate with an explicit **exact DNS subjectAltName**
   equal to the approved `deployment.listen.hostname`, appropriate
   server-authentication purpose, valid start/end dates and a sufficiently
   strong approved key. A Common Name alone or a wildcard-only SAN does
   not satisfy the current exact-name REPOCACHE fixture contract.
3. Transfer the end-entity certificate, required intermediate chain
   and private key through a **trusted operator-controlled channel**.
   Verify CA provenance and CA public-key fingerprint out-of-band.
   A file bundled alongside an unauthenticated installer is not a
   trust anchor. Do not disable TLS checks to make an untrusted or
   expired certificate pass.
4. Stage certificate and key as two distinct regular files, for example
   `/etc/repocache/tls/server-chain.pem` and
   `/etc/repocache/tls/server-key.pem`. The reviewed install-v1 input
   contains **references only**, never PEM strings. Protect the private
   key as root-only mode `0600`, and preserve strictly owned, non-writable
   parent directories. Public certificate mode `0644` or `0600` is
   allowed by the detached fixture inspector; the real installed-host
   ownership, ACLs, mount and SELinux labels need their own checks.
   Never weaken the key's permissions merely to satisfy an untrusted
   NGINX syntax check or make it accessible to the REPOCACHE service user.

These commands are **local read-only review examples**, not an installer.
Replace the paths and DNS name in a trusted operator session. Do **not**
paste raw output containing internal hostnames, subjects, paths or issuers
into public PRs or this conversation.

```sh
# Set these only in a trusted operator shell; do not print them in logs.
# Use a shell with pipefail so a failed upstream OpenSSL command cannot pass.
set -o pipefail
CERT=/etc/repocache/tls/server-chain.pem
KEY=/etc/repocache/tls/server-key.pem
CA=/absolute/path/to/independently/trusted/public-ca.pem
DNS=cache.example.invalid

# Inspect leaf identity, validity and intended server authentication.
openssl x509 -in "$CERT" -noout -dates -ext subjectAltName
openssl x509 -in "$CERT" -noout -ext extendedKeyUsage
openssl x509 -in "$CERT" -noout -checkend 0

# Use the *independently verified* CA; a successful command does not
# authenticate that CA's origin. For intermediate chains, provide the
# authenticated intermediate certificates to -untrusted separately.
openssl verify -purpose sslserver -verify_hostname "$DNS" \
  -CAfile "$CA" "$CERT"

# Prove that certificate and private key encode the same public key.
# Only SHA-256 digests of public key DER leave these pipelines.
openssl x509 -in "$CERT" -pubkey -noout |
  openssl pkey -pubin -outform DER | openssl sha256
openssl pkey -in "$KEY" -pubout -outform DER | openssl sha256
```

The two digest lines must match **exactly**, and every OpenSSL command
must succeed. Inspect the DNS SAN separately from the extended-key-usage
output: repeated `-ext` switches on some OpenSSL builds can suppress the
earlier extension instead of displaying both. If an extension is absent,
review the certificate purpose under the approved PKI policy, do not
infer it was displayed. The commands require a shell supporting
`pipefail`; never interpret only the final pipeline process exit status
as proof of earlier OpenSSL successes. Do not automate
a passphrase prompt or store it in command arguments. Failures, missing
intermediates, inaccessible files, symlinks, mutable/hardlinked keys,
unreviewed ACL/xattr/SELinux state and untrusted parent directories are
**NOT VERIFIED/refusal**, not reasons to skip checking.

## Configuration and activation boundary

- Use only `deployment.tls.mode=operator-provided` and valid canonical
  certificate/key paths in the [reviewed install-v1 contract](../architecture/SERVER_INSTALLATION_CONTRACT_V1.md).
  Do not copy private key bytes into NGINX configuration, catalog, status
  output, issue comments, artifacts or request logs.
- The generated HTTPS listener is an inert candidate until the
  authenticated root-owned installer and NGINX privilege boundary
  separately verify effective package/service ownership, TLS key
  accessibility, complete chain and SAN, independent signed candidate
  provenance and working previous configuration. On AlmaLinux, SELinux
  must remain enforcing; its installed labels and actual native service
  access still require review. `nginx -t` alone is **insufficient**:
  stock AlmaLinux 10 testing has demonstrated non-rejection of some
  malformed or mismatched keys in configuration syntax checks.
- `deployment.firewall.modify=false` forbids REPOCACHE firewall edits;
  it **does not guarantee that existing rules block a non-loopback
  HTTPS listener**. Inspect both the effective listener and firewall
  backend, approved bind/port and rules as separate native acceptance
  criteria before activation. Explicit operator intent to edit firewall
  rules is not yet an implemented write or an authorization.
- REPOCACHE v0.6.0 has no automatic HTTP exception and no implicit
  inbound port opening. Do not publish an HTTP listener merely because
  a disposable fixture served a successful HTTPS handshake.

## Renewal, replacement and evidence

Treat renewal as a new **operator-authorized certificate generation**, not
in-place editing of the last-known-good key. Independently validate
issuer/SAN/validity and exact key match *before* staging. Retain recoverable
previous managed NGINX generation and operator-controlled key material.
After successful staged syntax, approved controlled reload and
observed TLS peer identity, verify old certificate/key bytes and any
firewall rules were not modified by REPOCACHE. On failure, preserve
previous working NGINX and recover using the #31 protected journal
procedure; never destroy the only known-good credential pair.

The [non-privileged loopback TLS receipt](SERVER_VM_TLS_IDENTITY_RECEIPT_V1.md)
may later provide a sanitized observed CA-validated TLS handshake and exact
DNS SAN from a booted VM. It does not prove real CA provenance, private
key protection, installed NGINX source, firewall exposure, SELinux labels,
reload reversibility or genuine production signing. Preserve all five
original #30 acceptance criteria and the #19 booted-host campaign:
this guide establishes **documentation readiness, not native PASS**.
