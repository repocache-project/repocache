# Server preflight document descriptor boundary (#26)

The read-only `scripts/server_v06_preflight.py` now opens an absolute
installation JSON path from `/` using a bounded sequence of
`O_DIRECTORY|O_NOFOLLOW` file descriptors. It refuses symlinked ancestors
as well as a symlinked leaf, non-canonical components, oversized paths and
ambiguous names. After opening the leaf by parent descriptor it checks that
the named inode still agrees with the read descriptor and validates stable
metadata before parsing the bounded JSON bytes. All file descriptors are
closed on success or refusal.

This hardening prevents document traversal through otherwise safe-looking
symlinked ancestors; it does not authenticate the source package, root
operator consent, installed NGINX/systemd or a native SELinux context.
No files are written and no package/service operations are enabled. The
preflight remains `NOT VERIFIED` without the original host acceptance.
