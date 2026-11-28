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


GROUP = '''id() { case "$1" in -u) echo 1001 ;; -g) echo 1002 ;; esac; }
stat() { echo 108; }
ci_kvm_access_mode() { echo group; }
'''
CONFIRMED = '''ci_kvm_probe() {
  printf '%s\\n' '{"return":{"enabled":true,"present":true},"id":"kvm"}'
}
'''


def test_group_access_drops_root_ids_and_all_capabilities(tmp_path):
    out = shell(GROUP + CONFIRMED + '''ci_qemu_select "$1"
printf '%s\\n' "${qemu_cmd[@]}"
printf 'mode=%s\\n' "$accel"
''', tmp_path)
    assert "mode=kvm" in out
    assert out.splitlines()[-14:] == [
        "/usr/bin/sudo", "-n", "--", "/usr/bin/setpriv", "--reuid=1001",
        "--regid=1002", "--groups=108", "--inh-caps=-all",
        "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
        "--", "/usr/bin/qemu-system-x86_64", "mode=kvm",
    ]


def test_failed_probe_falls_back_to_unprivileged_tcg(tmp_path):
    out = shell(GROUP + '''ci_kvm_probe() { return 1; }
ci_qemu_select "$1"
printf '%s %s\\n' "$accel" "${qemu_cmd[*]}"
''', tmp_path)
    assert out.endswith("tcg qemu-system-x86_64\n")


def test_group_command_refuses_root_or_invalid_ids(tmp_path):
    for uid, gid, group in [(0, 1002, 108), (1001, 0, 108), (1001, 1002, 0),
                            (1001, 1002, "invalid")]:
        out = shell('''ci_kvm_access_mode() { echo group; }
uid="$2"; gid="$3"; group="$4"
id() { case "$1" in -u) echo "$uid" ;; -g) echo "$gid" ;; esac; }
stat() { echo "$group"; }
ci_kvm_probe() { exit 42; }
ci_qemu_select "$1"
printf '%s %s\\n' "$accel" "${qemu_cmd[*]}"
''', tmp_path, uid, gid, group)
        assert out.endswith("tcg qemu-system-x86_64\n")


def test_direct_access_still_probes_and_unavailable_skips_probe(tmp_path):
    out = shell(CONFIRMED + '''ci_kvm_access_mode() { echo direct; }
ci_qemu_select "$1"
test "$accel" = kvm
test "${qemu_cmd[*]}" = qemu-system-x86_64
ci_kvm_access_mode() { echo unavailable; }
ci_kvm_probe() { exit 42; }
ci_qemu_select "$1"
test "$accel" = tcg
''', tmp_path)
    assert "selected QEMU acceleration=tcg" in out


def test_successful_exit_without_explicit_kvm_confirmation_falls_back(tmp_path):
    for reply in ('{"return":{}}', '{"return":{"enabled":false,"present":true},"id":"kvm"}',
                  '{"return":{"enabled":true,"present":false},"id":"kvm"}',
                  '{"return":{"enabled":"true","present":true},"id":"kvm"}', 'invalid'):
        out = shell('''ci_kvm_access_mode() { echo direct; }
reply="$2"
ci_kvm_probe() { printf '%s\\n' "$reply"; }
ci_qemu_select "$1"
test "$accel" = tcg
''', tmp_path, reply)
        assert "selected QEMU acceleration=tcg" in out


def test_resource_budget():
    assert shell('ci_qemu_resources 2 4194304 kvm debian13; echo "$vm_cpus $vm_ram"') == "2 3072\n"
    assert shell('ci_qemu_resources 4 10485760 kvm debian13; echo "$vm_cpus $vm_ram"') == "3 4096\n"
    assert shell('ci_qemu_resources 4 7340032 kvm almalinux10; echo "$vm_cpus $vm_ram"') == "3 4096\n"
    assert shell('ci_qemu_resources 4 7340031 kvm almalinux10; echo "$vm_cpus $vm_ram"') == "3 3072\n"
    assert shell('ci_qemu_resources 4 4194304 kvm almalinux10; echo "$vm_cpus $vm_ram"') == "3 3072\n"
    assert shell('ci_qemu_resources 4 10485760 tcg debian13; echo "$vm_cpus $vm_ram"') == "2 3072\n"
    assert shell('ci_qemu_resources 4 10485760 tcg almalinux10; echo "$vm_cpus $vm_ram"') == "3 6144\n"


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
