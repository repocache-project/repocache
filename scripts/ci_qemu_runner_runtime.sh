#!/usr/bin/env bash
# Helpers for the disposable booted-VM harness; no changes to guest trust.
ci_kvm_access_mode() {
  if test -c /dev/kvm && test -r /dev/kvm && test -w /dev/kvm; then
    echo direct
  elif test "${GITHUB_ACTIONS:-}" = true &&
       test "${RUNNER_ENVIRONMENT:-}" = github-hosted &&
       test "$(id -u)" != 0 && test -c /dev/kvm && ! test -L /dev/kvm &&
       test "$(stat -c '%u:%G' /dev/kvm)" = 0:kvm; then
    echo group
  else
    echo unavailable
  fi
}
ci_kvm_group_command() {
  local uid gid kvm_gid
  uid="$(id -u)" || return 1
  gid="$(id -g)" || return 1
  kvm_gid="$(stat -c '%g' /dev/kvm)" || return 1
  [[ "$uid" =~ ^[1-9][0-9]*$ && "$gid" =~ ^[1-9][0-9]*$ &&
     "$kvm_gid" =~ ^[1-9][0-9]*$ ]] || return 1
  # Hosted runners allow noninteractive root sudo for system tooling, not
  # necessarily sudo -u/-g. Only setpriv runs privileged; QEMU does not.
  qemu_cmd=(/usr/bin/sudo -n -- /usr/bin/setpriv
    "--reuid=$uid" "--regid=$gid" "--groups=$kvm_gid"
    --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs
    -- /usr/bin/qemu-system-x86_64)
}
ci_kvm_probe() {
  printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"query-kvm","id":"kvm"}' '{"execute":"quit"}' |
    timeout --kill-after=2 15 "${qemu_cmd[@]}" -machine accel=kvm -cpu host \
      -smp 1 -m 128 -nodefaults -display none -monitor none -serial none -S -qmp stdio
}
ci_kvm_confirmed() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8", errors="replace") as stream:
    for line in stream:
        try:
            reply = json.loads(line)
        except ValueError:
            continue
        if isinstance(reply, dict) and reply.get("id") == "kvm":
            value = reply.get("return")
            if (isinstance(value, dict) and value.get("enabled") is True
                    and value.get("present") is True):
                sys.exit(0)
sys.exit(1)
PY
}
ci_qemu_select() {
  local evidence="$1" mode ready=yes
  mode="$(ci_kvm_access_mode)"
  accel=tcg
  qemu_cmd=(qemu-system-x86_64)
  if test "$mode" = group && ! ci_kvm_group_command; then
    ready=no
  fi
  if test "$mode" != unavailable && test "$ready" = yes &&
     ci_kvm_probe > "$evidence/kvm-probe.txt" 2>&1 &&
     ci_kvm_confirmed "$evidence/kvm-probe.txt"; then
    accel=kvm
  else
    qemu_cmd=(qemu-system-x86_64)
    if test "$mode" != unavailable; then
      echo 'KVM initialization not confirmed; using TCG (see kvm-probe.txt if present).'
    fi
  fi
  printf 'KVM access=%s; selected QEMU acceleration=%s\n' "$mode" "$accel" |
    tee -a "$evidence/runner.txt"
}
ci_qemu_resources() {
  local host_cpus="$1" available_kib="$2" acceleration="$3" platform="$4"
  vm_cpus=2
  vm_ram=3072
  # Retain the faster observed AlmaLinux TCG profile, but restore the
  # smaller Debian TCG baseline. These are tuning defaults, not benchmarks.
  if test "$acceleration" != kvm && test "$platform" != almalinux10; then
    return 0
  fi
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
