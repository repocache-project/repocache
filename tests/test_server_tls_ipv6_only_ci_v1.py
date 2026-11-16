"""Regressions for the real, deliberately unprivileged IPv6-only TLS CI."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_socket_smoke_denies_ipv4_and_proves_tls_authority():
    source = (ROOT / "scripts/ci_server_tls_ipv6_only_native.py").read_text()
    compile(source, "ci_server_tls_ipv6_only_native.py", "exec")
    for part in (
        "REPOCACHE_DISPOSABLE_NGINX_IPV6", "os.geteuid() != 0",
        'Path("/.dockerenv")', "socket.AF_INET6", "socket.AF_INET",
        "errno.ECONNREFUSED", "ipv6only=on", "SYNTHETIC_TLS_FIXTURE_INVALID",
        "STOCK_NGINX_IPV6_SYNTAX_INVALID", "authorizes_nginx_activation",
        "authorizes_firewall_change", "ssl.create_default_context()",
        "synthetic.pem",
    ):
        assert part in source
    for forbidden in ("shell=True", "systemctl ", "firewall-cmd ", "os.chown("):
        assert forbidden not in source


def test_two_distro_workflow_is_a_disposable_nonprivileged_merge_gate():
    source = (ROOT / ".github/workflows/server-tls-ipv6-only-native.yml").read_text()
    for part in (
        "pull_request:", "merge_group:", "debian:trixie-slim",
        "almalinux:10", "docker build --pull",
        "docker run --rm --network none --read-only --user 65534:65534",
        "--cap-drop ALL --security-opt no-new-privileges",
        "target=/repo,readonly", "ci_server_tls_ipv6_only_native.py",
    ):
        assert part in source
    for forbidden in ("--network host", "--privileged", "sudo ", "systemctl ",
                      "semanage ", "firewall-cmd ", "docker push "):
        assert forbidden not in source
