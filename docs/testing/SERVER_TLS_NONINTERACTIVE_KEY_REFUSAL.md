# Noninteractive TLS private-key verification (#30)

The pinned fixture TLS pair reader passes an explicit **empty** password
to Python OpenSSL `SSLContext.load_cert_chain`. Python/OpenSSL may
otherwise try to prompt on an inherited terminal if the operator's key
is encrypted, violating the noninteractive preflight contract and
potentially creating an uncontrolled passphrase entry path.

An encrypted key now fails closed with the existing static
`TLS_MATERIAL_TLS_PAIR_OR_INODE_UNVERIFIED` result. There is no prompt,
password callback, subprocess, log emission or key/passphrase repair.
Unencrypted key material remains accepted only in pinned private fixture
directories with mode 0600; a real OpenSSL regression uses a disposable
password-protected test key and verifies its bytes are preserved.

Installed encrypted private keys are **not automatically supported**:
providing an approved secret broker or passphrase FD is a separate
architecture/security decision, not implicit operator input.
Real host-root, SELinux, NGINX and external CA/certificate authority
remain NOT VERIFIED for the #30/#19 operational gate.
