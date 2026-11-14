"""Workflow guard: native TLS rotation stays isolated and non-authorizing."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tls_rotation_script_and_native_matrix_are_explicitly_isolated():
    workflow = (ROOT / ".github/workflows/server-native-tls-rotation-recovery.yml").read_text()
    script = (ROOT / "scripts/ci_v06_nginx_tls_rotation_recovery.py").read_text()
    for required in (
        "debian:trixie-slim", "almalinux:10", "--network none",
        "--read-only", "--user 65534:65534", "--cap-drop ALL",
        "--security-opt no-new-privileges", "REPOCACHE_DISPOSABLE_TLS_ROTATION=1",
        "merge_group:", "persist-credentials: false",
    ):
        assert required in workflow
    for required in (
        "ROOT_DISALLOWED", "NATIVE_HOST_DISALLOWED",
        "MISMATCHED_TLS_PAIR_ACCEPTED", "TLS_ROTATION_NOT_OBSERVED_ON_WIRE",
        "ssl.PEM_cert_to_DER_cert", "conf.read_bytes() == original",
        "ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)",
        "service.poll() is None", "service.wait(timeout=6)",
    ):
        assert required in script
    for forbidden in ("shell=True", "systemctl", "sudo ", "/etc/repocache/tls",
                      "iptables", "firewall-cmd"):
        assert forbidden not in script
