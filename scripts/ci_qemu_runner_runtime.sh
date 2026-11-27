#!/usr/bin/env bash
# Helpers for the disposable booted-VM harness; no changes to guest trust.
ci_kvm_access_mode() {
  if test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm; then
    echo direct
  elif test "${GITHUB_ACTIONS:-}" = true &&
       test "${RUNNER_ENVIRONMENT:-}" = github-hosted &&
       test "$(id -u)" != 0 && test -c /dev/kvm && ! test -L /dev/kvm &&
       test "$(stat -c '%u:%G' /dev/kvm)" = 0:kvm; then
    # Run only QEMU as the existing unprivileged UID with the device group.
    echo group
  else
    echo unavailable
  fi
}
ci_kvm_probe() {
  printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"quit"}' |
    timeout --kill-after=2 15 "${qemu_cmd[@]}" -machine accel=kvm -cpu host \
      -smp 1 -m 128 -nodefaults -display none -monitor none -serial none -S -qmp stdio
}
ci_qemu_select() {
  local evidence="$1" mode
  mode="$(ci_kvm_access_mode)"
  accel=tcg
  qemu_cmd=(qemu-system-x86_64)
  if test "$mode" = group; then
    qemu_cmd=(sudo -n -u "#$(id -u)" -g kvm -- /usr/bin/qemu-system-x86_64)
  fi
  if test "$mode" != unavailable && ci_kvm_probe > "$evidence/kvm-probe.txt" 2>&1; then
    accel=kvm
  else
    qemu_cmd=(qemu-system-x86_64)
  fi
  printf 'KVM access=%s; selected QEMU acceleration=%s\n' "$mode" "$accel" |
    tee -a "$evidence/runner.txt"
}
ci_qemu_resources() {
  local host_cpus="$1" available_kib="$2"
  vm_cpus=2
  vm_ram=3072
  # Keep at least one logical CPU and 3 GiB available to the runner.
  if test "$host_cpus" -ge 4; then vm_cpus=3; fi
  if test "$available_kib" -ge 9437184; then vm_ram=6144; fi
}
ci_waitssh() {
  local previous="${1:-}" observed started=$SECONDS
  while :; do
    if observed="$(sshguest 'test "$(cat /proc/1/comm)" = systemd && cat /proc/sys/kernel/random/boot_id' 2>/dev/null)" &&
       [[ "$observed" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] &&
       test "$observed" != "$previous"; then
      return 0
    fi
    if test "$((SECONDS - started))" -ge 600; then
      echo 'Native systemd/SSH or new kernel boot not ready in 10 min' >&2
      return 1
    fi
    sleep 2
  done
}
