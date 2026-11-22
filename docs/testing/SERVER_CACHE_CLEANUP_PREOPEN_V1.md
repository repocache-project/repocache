# #95 — read-only cache cleanup open(2) refusal boundary

An explicit force-cleanup feature must never treat the on-disk
NGINX cache as a trusted pathname tree. The existing **fixture-only**
read-only preview verifies owner markers and descriptor-pinned `levels=1:2`
cache contents before reporting potential allocated/apparent bytes.

For security, the scanner now refuses a leaf or directory by
**lstat-like** `os.stat(..., follow_symlinks=False)` metadata checks
*before calling os.open*: this rejects FIFO, device/socket nodes,
symlinks, wrong type, hardlinks on files, unsafe permission bits,
untrusted owner and foreign mount. Merely opening a special device can
have side effects even with `O_NONBLOCK`. The descriptor's identity is
still rechecked immediately after open and after scanning. A race is
**not** proof that a future destructive action is safe: no installed
root/NGINX or concurrent transfer authority exists in this preview.

`tests/test_server_repository_cache_cleanup_preview_v1.py` now
monkeypatches the real `os.open` seam to prove unsafe leaf and
directory types are rejected **before opening**, without affecting
external files. The scanner never deletes cache bytes or modifies a
repository configuration.

Original #95 AC4 (durable normal removal, true safe authorized
force-cleanup, live transfers, isolation and native SELinux) remains
**NOT VERIFIED**, pending a separate, authenticated, locked and
recoverable installed implementation and final booted VM evidence.
