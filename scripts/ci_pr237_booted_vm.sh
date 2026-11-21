#!/usr/bin/env bash
# Native QEMU smoke only: no owner signing, no REPOCACHE production installation.
set -Eeuo pipefail
umask 077
case "$PR237_PLATFORM" in
  debian13) PR237_PLATFORM_ID=debian ;;
  almalinux10) PR237_PLATFORM_ID=almalinux ;;
  *) exit 2 ;;
esac
out="$PWD/pr237-vm-evidence"
mkdir -p "$out"
tmp="$(mktemp -d)"
stage=initial
scenario="${PR237_SCENARIO:-smoke}"
case "$scenario" in smoke|native-installer) ;; *) echo 'Invalid VM scenario' >&2; exit 2;; esac
accel=unknown
sha="$(git rev-parse HEAD)"
finish() {
  rc=$?
  trap - EXIT
  if test -f "$tmp/qemu.pid"; then kill "$(cat "$tmp/qemu.pid")" 2>/dev/null || true; fi
  if test -f "$tmp/serial.log"; then tail -c 65536 "$tmp/serial.log" > "$out/serial-tail.log" || true; fi
  {
    echo "## PR #237 — $PR237_PLATFORM $scenario experimental booted VM"
    echo "Source HEAD: $sha"
    echo "Image: $PR237_IMAGE_URL"
    echo "Expected image SHA512: $PR237_IMAGE_SHA512"
    echo "Expected image SHA256: $PR237_IMAGE_SHA256"
    echo "Acceleration: $accel (KVM is not officially supported on hosted runners)"
    echo "Last phase: $stage"
    if test "$rc" = 0; then echo "VM exercise: PASS"; else echo "VM exercise: FAIL or NOT VERIFIED (inspect phase and logs)"; fi
    echo "Owner-signed installed worker / actual publisher acceptance: NOT VERIFIED"
    if test -f "$out/facts.txt"; then
      echo '### Guest facts'
      echo '~~~'
      head -40 "$out/facts.txt"
      echo '~~~'
    fi
  } > "$out/summary.md"
  rm -rf "$tmp"
  exit "$rc"
}
trap finish EXIT
printf '%s\n' "$sha" > "$out/sha.txt"
stage=runner-probe
{
  uname -a
  id
  qemu-system-x86_64 --version | head -1
  echo "kvm_device=$(test -c /dev/kvm && echo yes || echo no)"
  echo "kvm_rw=$(test -r /dev/kvm && test -w /dev/kvm && echo yes || echo no)"
  df -h "$tmp"
} > "$out/runner.txt"
if test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm; then accel=kvm; else accel=tcg; fi
stage=image-integrity
case "$PR237_IMAGE_URL" in
  https://cloud.debian.org/images/cloud/trixie/*|https://repo.almalinux.org/almalinux/10/cloud/x86_64/images/*) ;;
  *) echo "Refusing unexpected image host" >&2; exit 2 ;;
esac
test -n "$PR237_IMAGE_SHA512$PR237_IMAGE_SHA256"
curl --proto '=https' --tlsv1.2 -fL --retry 3 --retry-delay 5 --max-time 1200 -o "$tmp/base.qcow2" "$PR237_IMAGE_URL"
if test -n "$PR237_IMAGE_SHA512"; then
  printf '%s  %s\n' "$PR237_IMAGE_SHA512" "$tmp/base.qcow2" | sha512sum -c -
fi
if test -n "$PR237_IMAGE_SHA256"; then
  printf '%s  %s\n' "$PR237_IMAGE_SHA256" "$tmp/base.qcow2" | sha256sum -c -
fi
sha256sum "$tmp/base.qcow2" > "$out/image-sha256.txt"
qemu-img info "$tmp/base.qcow2" > "$out/image-info.txt"
qemu-img create -f qcow2 -F qcow2 -b "$tmp/base.qcow2" "$tmp/disk.qcow2" >/dev/null
stage=cloud-init-seed
ssh-keygen -q -t ed25519 -N '' -f "$tmp/id_ed25519"
pub="$(cat "$tmp/id_ed25519.pub")"
cat > "$tmp/user-data" <<EOF
#cloud-config
users:
  - name: pr237ci
    shell: /bin/bash
    lock_passwd: true
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - $pub
ssh_pwauth: false
disable_root: true
EOF
printf 'instance-id: pr237-%s\nlocal-hostname: pr237-%s\n' "$PR237_PLATFORM" "$PR237_PLATFORM" > "$tmp/meta-data"
cloud-localds "$tmp/seed.iso" "$tmp/user-data" "$tmp/meta-data"
stage=qemu-boot
cpu=max
if test "$accel" = kvm; then cpu=host; fi
qemu-system-x86_64 -name pr237 -machine "accel=$accel" -cpu "$cpu" -m 3072 -smp 2 \
  -display none -monitor none -serial "file:$tmp/serial.log" \
  -drive "file=$tmp/disk.qcow2,if=virtio,format=qcow2" \
  -drive "file=$tmp/seed.iso,if=virtio,format=raw,readonly=on" \
  -netdev 'user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22' \
  -device virtio-net-pci,netdev=n0 -daemonize -pidfile "$tmp/qemu.pid"
sshguest() {
  ssh -i "$tmp/id_ed25519" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$tmp/known_hosts" -o LogLevel=ERROR -o ConnectTimeout=4 \
    -p 2222 pr237ci@127.0.0.1 "$@"
}
waitssh() {
  i=0
  until sshguest 'test "$(cat /proc/1/comm)" = systemd' >/dev/null 2>&1; do
    i=$((i+1))
    if test "$i" -ge 120; then echo 'Native systemd/SSH not ready in 10 min' >&2; return 1; fi
    sleep 5
  done
}
prepare_pinned_synthetic_source() {
  stage=pinned-pr249-synthetic-candidate
  # This combines already-reviewed source only in a local throwaway worktree.
  # It never fetches publisher keys or modifies the #249 PR/branch.
  PR249_SHA=fba69bc8baad0dc6b5d6be7d59812572928f5efa
  git fetch --no-tags origin +refs/heads/fix/76-repository-transfer-v06-candidate-20261107:refs/remotes/origin/pr249
  test "$(git rev-parse refs/remotes/origin/pr249)" = "$PR249_SHA"
  git worktree add --detach "$tmp/combined-source" "$sha" >/dev/null
  git -C "$tmp/combined-source" switch -c pr237-synthetic-vm-merge >/dev/null
  git -C "$tmp/combined-source" config user.email "pr237-fixture@repocache.invalid"
  git -C "$tmp/combined-source" config user.name "PR237 disposable synthetic CI"
  git -C "$tmp/combined-source" merge --no-ff --no-edit "$PR249_SHA" >/dev/null
  combined_sha="$(git -C "$tmp/combined-source" rev-parse HEAD)"
  printf 'pr237_head=%s\npr249_dependency=%s\ncombined_disposable=%s\n' "$sha" "$PR249_SHA" "$combined_sha" > "$out/synthetic-source-provenance.txt"
  git -C "$tmp/combined-source" archive HEAD | gzip -1 > "$tmp/combined-source.tar.gz"
  scp -i "$tmp/id_ed25519" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
    -o "UserKnownHostsFile=$tmp/known_hosts" -o LogLevel=ERROR \
    -P 2222 "$tmp/combined-source.tar.gz" pr237ci@127.0.0.1:combined.tar.gz
  sshguest 'mkdir -p ~/combined && tar -xf ~/combined.tar.gz -C ~/combined'
}
waitssh
stage=inspect-booted-guest
sshguest 'cloud-init status --wait; cat /etc/os-release; uname -a; cat /proc/1/comm; systemctl is-system-running || true; systemd-detect-virt || true; id; command -v getenforce && getenforce || true' > "$out/facts.txt" 2>&1
boot_before="$(sshguest 'cat /proc/sys/kernel/random/boot_id')"
stage=copy-exact-source
git archive HEAD | gzip -1 > "$tmp/source.tar.gz"
scp -i "$tmp/id_ed25519" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
  -o "UserKnownHostsFile=$tmp/known_hosts" -o LogLevel=ERROR \
  -P 2222 "$tmp/source.tar.gz" pr237ci@127.0.0.1:source.tar.gz
sshguest 'mkdir -p ~/source && tar -xf ~/source.tar.gz -C ~/source'
if test "$scenario" = native-installer; then
  stage=prepare-fresh-native-installer-guest
  sshguest "sudo bash /home/pr237ci/source/scripts/ci_pr237_guest.sh '$PR237_PLATFORM' prepare-installer" > "$out/installer-prerequisites.txt" 2>&1 || { cat "$out/installer-prerequisites.txt"; exit 1; }
  prepare_pinned_synthetic_source
  stage=synthetic-worker-native-placement
  sshguest "sudo /usr/bin/python3 -B /home/pr237ci/source/scripts/ci_pr237_synthetic_worker_guest.py /home/pr237ci/combined '$combined_sha'" > "$out/synthetic-installed-worker.txt" 2>&1 || { cat "$out/synthetic-installed-worker.txt"; exit 1; }
  stage=real-native-package-install-through-signed-worker
  sshguest "sudo /usr/bin/python3 -B /home/pr237ci/source/scripts/ci_pr237_native_package_guest.py '$PR237_PLATFORM_ID' install" > "$out/native-install.txt" 2>&1 || { cat "$out/native-install.txt"; exit 1; }
  stage=native-installer-kernel-reboot
  sshguest 'sudo systemctl reboot' >/dev/null 2>&1 || true
  sleep 8
  waitssh
  boot_after="$(sshguest 'cat /proc/sys/kernel/random/boot_id')"
  test "$boot_after" != "$boot_before"
  printf 'before=%s\\nafter=%s\\n' "$boot_before" "$boot_after" > "$out/installer-reboot-ids.txt"
  stage=native-installer-after-reboot
  sshguest "sudo /usr/bin/python3 -B /home/pr237ci/source/scripts/ci_pr237_native_package_guest.py '$PR237_PLATFORM_ID' after" > "$out/native-install-after-reboot.txt" 2>&1 || { cat "$out/native-install-after-reboot.txt"; exit 1; }
  stage=complete
  exit 0
fi
stage=before-reboot-nginx
sshguest "sudo bash /home/pr237ci/source/scripts/ci_pr237_guest.sh '$PR237_PLATFORM' prepare" > "$out/before-reboot.txt" 2>&1 || { cat "$out/before-reboot.txt"; exit 1; }
stage=kernel-reboot
sshguest 'sudo systemctl reboot' >/dev/null 2>&1 || true
sleep 8
waitssh
boot_after="$(sshguest 'cat /proc/sys/kernel/random/boot_id')"
test "$boot_after" != "$boot_before"
printf 'boot_before=%s\nboot_after=%s\n' "$boot_before" "$boot_after" > "$out/reboot-ids.txt"
stage=after-reboot-nginx
sshguest "sudo bash /home/pr237ci/source/scripts/ci_pr237_guest.sh '$PR237_PLATFORM' after" > "$out/after-reboot.txt" 2>&1 || { cat "$out/after-reboot.txt"; exit 1; }
prepare_pinned_synthetic_source
stage=synthetic-native-worker-placement
sshguest "sudo /usr/bin/python3 -B /home/pr237ci/source/scripts/ci_pr237_synthetic_worker_guest.py /home/pr237ci/combined '$combined_sha'" > "$out/synthetic-installed-worker.txt" 2>&1 || { cat "$out/synthetic-installed-worker.txt"; exit 1; }
stage=synthetic-pending-journal
sshguest "sudo bash /home/pr237ci/source/scripts/ci_pr237_guest.sh '$PR237_PLATFORM' journal-prepare" > "$out/pending-journal-before-reboot.txt" 2>&1 || { cat "$out/pending-journal-before-reboot.txt"; exit 1; }
stage=second-guest-kernel-reboot
boot_second_before="$(sshguest 'cat /proc/sys/kernel/random/boot_id')"
sshguest 'sudo systemctl reboot' >/dev/null 2>&1 || true
sleep 8
waitssh
boot_second_after="$(sshguest 'cat /proc/sys/kernel/random/boot_id')"
test "$boot_second_after" != "$boot_second_before"
printf 'before_second=%s\nafter_second=%s\n' "$boot_second_before" "$boot_second_after" > "$out/second-reboot-ids.txt"
stage=synthetic-pending-refusal-after-reboot
sshguest "sudo bash /home/pr237ci/source/scripts/ci_pr237_guest.sh '$PR237_PLATFORM' journal-after" > "$out/pending-journal-after-reboot.txt" 2>&1 || { cat "$out/pending-journal-after-reboot.txt"; exit 1; }
stage=complete
