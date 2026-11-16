"""Contract guard for native TLS negotiation and HTTP downgrade (#30)."""
from pathlib import Path


def test_tls_protocol_and_https_only_smoke_contract():
    source = (Path(__file__).resolve().parents[1] /
              "scripts/ci_server_tls_listener_native.py").read_text()
    for required in (
        "ssl.TLSVersion.TLSv1_2", "ssl.TLSVersion.TLSv1_3",
        "pinned.minimum_version=version",
        "pinned.maximum_version=version",
        "pinned.verify_mode=ssl.CERT_REQUIRED",
        "pinned.load_verify_locations(cafile=str(cert))",
        'assert b"200 OK" not in plaintext',
        'assert b"repocache-https" not in plaintext',
        "session.version()",
        "REPOCACHE_DISPOSABLE_NGINX_SMOKE",
    ):
        assert required in source
    for forbidden in ("shell=True", "systemctl", "os.remove(", "os.unlink("):
        assert forbidden not in source
