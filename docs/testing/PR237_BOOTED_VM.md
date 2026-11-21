# PR #237 — experimental booted GitHub-hosted VMs

**Scope:** PR #237 only. Non-required CI job; no release or production approval.
The matrix boots actual pinned Debian 13 and AlmaLinux 10 x86_64 cloud images
as full QEMU VMs on separate ubuntu-24.04 GitHub-hosted runners. Image URLs
are upstream HTTPS, build numbers fixed, and independently recorded SHA
digests are mandatory and fail closed. Debian SHA512 is recorded from the
Debian Cloud Image Finder exact build; Alma SHA256 is published on the
official AlmaLinux current x86_64 GenericCloud download page. Never silently
update the image or accept a mismatch.

The job probes /dev/kvm and labels real KVM versus QEMU TCG fallback.
GitHub does not officially support nested virtualization on standard runners.
A guest-specific ephemeral Ed25519 SSH key is used through a loopback-only
SSH forward. Neither the secret key nor the cloud-init seed nor a VM disk is
uploaded. Test artifacts are bounded and have 7-day retention.

Evidence includes actual guest OS/kernel, systemd PID1, SELinux enforcing
on AlmaLinux, root/manager, stock signed-distro NGINX APT/DNF installation,
masked/inactive service, distinct kernel boot IDs after a guest reboot,
mask persistence, systemd start/stop, local HTTP, and existing #237
journal/package-owner fixture tests on the booted system.

**NOT VERIFIED** even if green: owner-signed REPOCACHE installer/worker,
v2 native product transaction, interrupted installed-product recovery, safe
same-version repair, TLS/cache/log preservation, foreign service recovery,
real publisher trust, production safety and broader milestone gates. Stock
NGINX smoke and fixture tests must never be called signed-host acceptance.
All package manager operations are restricted to the disposable guests;
no host service is changed and no third-party action is used.

Failure at boot/image/cloud-init/SELinux/package-test stage is reported as
FAIL or NOT VERIFIED with stage-specific logs, not silently skipped. Keep
this an experiment until the maintainer decides whether to extend it.
