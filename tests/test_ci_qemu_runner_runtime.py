"""Exercise acceleration, sizing and reboot readiness without a real VM."""
import subprocess
from pathlib import Path

HELPER = Path(__file__).resolve().parents[1] / "scripts/ci_qemu_runner_runtime.sh"


def shell(body, *args):
    return subprocess.run(
        ["bash", "-Eeuo", "pipefail", "-c", 'source "$1"; shift; ' + body,
         "test", str(HELPER), *map(str, args)],
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout


def test_group_access_uses_same_uid_and_no_root_or_global_permissions(tmp_path):
    out = shell('''ci_kvm_access_mode() { echo group; }
ci_kvm_probe() { printf '%s\\n' "${qemu_cmd[@]}"; }
ci_qemu_select "$1"
cat "$1/kvm-probe.txt"
printf 'mode=%s\\n' "$accel"
''', tmp_path)
    assert "mode=kvm" in out
    assert "sudo\n-n\n-u\n#" in out
    assert "\n-g\nkvm\n--\n/usr/bin/qemu-system-x86_64\n" in out


def test_failed_probe_falls_back_to_unprivileged_tcg(tmp_path):
    out = shell('''ci_kvm_access_mode() { echo group; }
ci_kvm_probe() { return 1; }
ci_qemu_select "$1"
printf '%s %s\\n' "$accel" "${qemu_cmd[*]}"
''', tmp_path)
    assert out.endswith("tcg qemu-system-x86_64\n")


def test_direct_access_still_probes_and_unavailable_skips_probe(tmp_path):
    out = shell('''ci_kvm_access_mode() { echo direct; }
ci_kvm_probe() { test "${qemu_cmd[*]}" = qemu-system-x86_64; }
ci_qemu_select "$1"
test "$accel" = kvm
ci_kvm_access_mode() { echo unavailable; }
ci_kvm_probe() { echo unexpected >&2; exit 42; }
ci_qemu_select "$1"
test "$accel" = tcg
''', tmp_path)
    assert "selected QEMU acceleration=tcg" in out


def test_resource_budget():
    assert shell('ci_qemu_resources 2 4194304; echo "$vm_cpus $vm_ram"') == "2 3072\n"
    assert shell('ci_qemu_resources 4 10485760; echo "$vm_cpus $vm_ram"') == "3 6144\n"
    assert shell('ci_qemu_resources 4 4194304; echo "$vm_cpus $vm_ram"') == "3 3072\n"


def test_reboot_wait_rejects_old_boot_and_malformed_id(tmp_path):
    old = "11111111-1111-1111-1111-111111111111"
    new = "22222222-2222-2222-2222-222222222222"
    out = shell('''counter="$1/count"
printf '0' > "$counter"
# The SSH function runs in a command-substitution subshell: use a file.
old="$2"; new="$3"
sshguest() {
  local count
  count=$(cat "$counter")
  printf '%s' "$((count + 1))" > "$counter"
  case "$count" in 0) echo "$old" ;; 1) echo invalid ;; *) echo "$new" ;; esac
}
sleep() { :; }
ci_waitssh "$old"
cat "$counter"
''', tmp_path, old, new)
    assert out == "3"
