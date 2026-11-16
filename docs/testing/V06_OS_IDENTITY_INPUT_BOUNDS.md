# Bounded native OS identity validation — v0.6.0 Stage A (#26)

The pure `validate_os_identity` API is also callable with a Python string,
not only through the pre-existing bounded native `/etc/os-release` reader.
Both call paths now enforce a **16 KiB UTF-8 input boundary**. The direct API
checks character count before allocation and then exact encoded byte size,
and rejects malformed Unicode with a fixed, redacted diagnostic.

Supported Debian 13/Python 3.13 and AlmaLinux 10/Python 3.12 validation is
unchanged. Unknown distributions and mismatched native Python still fail
closed. Additional non-identity keys in a normal UTF-8 OS release remain
ignored. No shell command, network, installation or host filesystem mutation
was introduced.

Tests cover oversized ASCII, multibyte UTF-8, invalid surrogates, redacted
errors, and valid native identity. These tests do not constitute full host
preflight, package provenance, systemd/SELinux or native VM acceptance.
