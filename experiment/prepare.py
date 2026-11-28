#!/usr/bin/env python3
"""Create a host-only experimental copy of the exact native VM harness."""
import os
from pathlib import Path

source = Path("scripts/ci_pr237_booted_vm.sh")
target = Path("scripts/ci_pr237_experimental_vm.sh")
body = source.read_text()
def replace_once(old, new):
    global body
    if body.count(old) != 1:
        raise SystemExit("Unexpected harness revision: " + old[:80])
    body = body.replace(old, new, 1)

replace_once('ci_qemu_select "$out"\n', '''ci_qemu_select "$out"
test "$accel" = kvm || { echo 'Experiment requires confirmed KVM'; exit 1; }
''')
replace_once('printf \'VM resources: %s vCPU, %s MiB\\n\' "$vm_cpus" "$vm_ram" | tee -a "$out/runner.txt"', '''case "$BENCH_PROFILE" in
  current) vm_cpus=3; vm_ram=6144 ;;
  two-four) vm_cpus=2; vm_ram=4096 ;;
  three-four) vm_cpus=3; vm_ram=4096 ;;
  two-eight) vm_cpus=2; vm_ram=8192 ;;
  *) exit 2 ;;
esac
host_cpus="$(nproc)"
available_kib="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)"
printf 'Host CPUs: %s; available KiB: %s\\n' "$host_cpus" "$available_kib" | tee -a "$out/runner.txt"
test "$host_cpus" -ge "$((vm_cpus+1))"
test "$available_kib" -ge "$(((vm_ram+3072)*1024))"
printf 'VM resources: %s vCPU, %s MiB\\n' "$vm_cpus" "$vm_ram" | tee -a "$out/runner.txt"''')
replace_once('curl --proto \'=https\' --tlsv1.2 -fL --retry 3 --retry-delay 5 --max-time 1200 -o "$tmp/base.qcow2" "$PR237_IMAGE_URL"', '''case "$BENCH_DELIVERY" in
  origin) curl --proto '=https' --tlsv1.2 -fL --retry 3 --retry-delay 5 --max-time 1200 -o "$tmp/base.qcow2" "$PR237_IMAGE_URL" ;;
  artifact)
    test -f "$BENCH_IMAGE" && test ! -L "$BENCH_IMAGE"
    cp --reflink=auto -- "$BENCH_IMAGE" "$tmp/base.qcow2" ;;
  *) exit 2 ;;
esac''')
replace_once('sha256sum "$tmp/base.qcow2" > "$out/image-sha256.txt"', '''sha256sum "$tmp/base.qcow2" > "$out/image-sha256.txt"
chmod 0444 "$tmp/base.qcow2"
if test "$BENCH_DELIVERY" = origin; then
  cp --reflink=auto -- "$tmp/base.qcow2" "$BENCH_IMAGE"
fi''')
replace_once('  phase_finish || true\n', '''  phase_finish || true
  if test -f "$out/image-sha256.txt"; then
    if ! sha256sum -c "$out/image-sha256.txt" > "$out/base-integrity-after.txt" 2>&1; then
      rc=1
    fi
  fi
''')
target.write_text(body)
