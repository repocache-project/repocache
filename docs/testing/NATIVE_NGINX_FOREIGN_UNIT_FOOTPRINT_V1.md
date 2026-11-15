# Foreign native NGINX systemd ownership — issue #27

## Foreign systemd NGINX units in fresh-install detection (#27)

A host may have a custom `nginx.service` or `nginx.socket` under
`/usr/local/lib/systemd/system` or runtime unit/drop-in fragments under
`/run/systemd/system`, even when the usual native package binary and
`/etc/nginx` tree are absent. The conservative read-only fresh-install
footprint now includes these explicit fixed service and socket paths.
Any existing entry (including a dangling link) refuses the clean-install
metadata transaction path; no foreign service is adopted or overwritten.
Absence of the expanded finite list is still merely `NOT VERIFIED`, not
native authority: a later installed worker must independently inventory
systemd aliases, loaded unit ownership, ports and NGINX processes under
its signed root transaction. Debian 13 and AlmaLinux 10 VM tests remain.
