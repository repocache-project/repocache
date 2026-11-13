"""Strict non-activating stock NGINX HTTPS listener candidate."""
import copy
import json
from pathlib import Path

import pytest

from repocache.server_nginx_tls_listener_candidate_v1 import (
    NativeTLSListenerCandidateError, render_native_tls_listener_candidate,
)

EXAMPLE = Path(__file__).resolve().parents[1]/"docs/examples/server-install-v1.json"


def doc():
    return json.loads(EXAMPLE.read_text())


def test_canonical_default_https_and_operator_key_reference():
    d=doc()
    before=copy.deepcopy(d)
    x=render_native_tls_listener_candidate(d)
    assert d == before
    assert x["server_context_fragment"] == (
        "listen 127.0.0.1:443 ssl;\n"
        "server_name cache.example.invalid;\n"
        "ssl_certificate /etc/repocache/tls/example-chain.pem;\n"
        "ssl_certificate_key /etc/repocache/tls/example-key.pem;\n"
        "ssl_protocols TLSv1.2 TLSv1.3;\n"
        "ssl_session_tickets off;\n"
        "server_tokens off;\n"
    )
    for key in ("operator_key_bytes_read","certificate_chain_verified",
                "key_pair_verified","hostname_authority_verified",
                "installed_nginx_access_verified","authorizes_firewall_change",
                "authorizes_nginx_activation"):
        assert x[key] is False


def test_ipv6_address_bracketed_not_double_quoted():
    d=doc()
    d["deployment"]["listen"]["bind_address"]="::1"
    result=render_native_tls_listener_candidate(d)
    assert "listen [::1]:443 ssl;" in result["server_context_fragment"]


@pytest.mark.parametrize("bad",[
    "/etc/repocache/tls/cert.pem;return 200",
    "/etc/repocache/tls/cert key.pem",
    "/etc/repocache/tls/$variable.pem",
    "/etc/repocache/tls/#comment.pem",
    "/etc/repocache/tls/../private.key",
    "/etc/repocache/tls/quote\".pem",
    "/etc/repocache/tls/has[bracket].pem",
])
def test_nginx_token_injection_refused(bad):
    d=doc()
    d["deployment"]["tls"]["certificate_file"]=bad
    with pytest.raises(NativeTLSListenerCandidateError,
                       match="NATIVE_TLS_CANDIDATE_INVALID"):
        render_native_tls_listener_candidate(d)


def test_identical_key_and_certificate_are_never_emitted():
    d=doc()
    d["deployment"]["tls"]["private_key_file"]=d["deployment"]["tls"]["certificate_file"]
    with pytest.raises(NativeTLSListenerCandidateError):
        render_native_tls_listener_candidate(d)


def test_unprivileged_candidate_does_not_open_firewall():
    d=doc()
    d["deployment"]["firewall"]["modify"]=True
    candidate=render_native_tls_listener_candidate(d)
    assert candidate["firewall_mutation_requested"] is True
    assert candidate["authorizes_firewall_change"] is False


def test_invalid_or_missing_expected_generation_is_refused():
    for value in (-1, True, "0"):
        d=doc()
        d["expected_state_generation"]=value
        with pytest.raises(NativeTLSListenerCandidateError):
            render_native_tls_listener_candidate(d)


def test_does_not_read_secrets_or_modify_files():
    import inspect
    from repocache import server_nginx_tls_listener_candidate_v1 as mod
    text=inspect.getsource(mod)
    assert "subprocess" not in text
    assert "os.open(" not in text
    assert "read_bytes(" not in text
    assert "systemctl" not in text
