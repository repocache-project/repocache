"""Regressions for immutable source identity and bounded decoded inputs (#95)."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from repocache.server_install_v1 import (
    InstallInputError, MAX_DOCUMENT_BYTES, parse_install_bytes,
    validate_install_document,
)


EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"


def document():
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("kind,key", [
    ("apt", "release_key_refs"), ("dnf", "gpg_key_refs"),
])
def test_rotated_trust_reference_does_not_create_distinct_identity(kind, key):
    source = document()
    repo = next(x for x in source["repositories"] if x["kind"] == kind)
    different = copy.deepcopy(repo)
    different["id"] = "new-name"
    different["layout"][key] = ["file:/etc/repocache/keys/rotated-public.gpg"]
    source["repositories"].append(different)
    with pytest.raises(InstallInputError, match="duplicate canonical"):
        validate_install_document(source)
    payload = json.dumps(source).encode("utf-8")
    with pytest.raises(InstallInputError, match="duplicate canonical"):
        parse_install_bytes(payload)


def test_different_upstream_layout_is_a_distinct_source():
    source = document()
    candidate = copy.deepcopy(source["repositories"][0])
    candidate["id"] = "separate-suite"
    candidate["layout"]["suites"] = ["bookworm"]
    source["repositories"].append(candidate)
    assert len(validate_install_document(source)["repositories"]) == 3


def test_direct_python_string_budget_rejects_before_encoding(monkeypatch):
    source = document()
    source["repositories"][0]["layout"]["suites"] = [
        "a" * (MAX_DOCUMENT_BYTES + 10)]
    def should_not_encode(*args, **kwargs):
        raise AssertionError("unexpected JSON encoding")
    monkeypatch.setattr(json.JSONEncoder, "iterencode", should_not_encode)
    with pytest.raises(InstallInputError, match="exceeds 1 MiB"):
        validate_install_document(source)


def test_direct_python_list_budget_rejects_before_encoding(monkeypatch):
    source = document()
    source["repositories"] = [None] * (MAX_DOCUMENT_BYTES + 1)
    def should_not_encode(*args, **kwargs):
        raise AssertionError("unexpected JSON encoding")
    monkeypatch.setattr(json.JSONEncoder, "iterencode", should_not_encode)
    with pytest.raises(InstallInputError, match="exceeds 1 MiB"):
        validate_install_document(source)


def test_recursive_and_non_json_values_rejected():
    source = document()
    cycle = []
    cycle.append(cycle)
    source["repositories"][0]["layout"]["suites"] = cycle
    with pytest.raises(InstallInputError, match="nesting"):
        validate_install_document(source)
    source = document()
    source["repositories"][0]["layout"]["suites"] = [object()]
    with pytest.raises(InstallInputError, match="JSON-compatible"):
        validate_install_document(source)


def test_exact_utf8_bytes_are_checked_after_bounded_walk():
    source = document()
    source["repositories"][0]["layout"]["suites"] = [
        "á" * (MAX_DOCUMENT_BYTES // 2)]
    with pytest.raises(InstallInputError, match="exceeds 1 MiB"):
        validate_install_document(source)


@pytest.mark.parametrize("key_size,expected", [
    (2049, "invalid length or whitespace"),
    (MAX_DOCUMENT_BYTES + 1, "exceeds 1 MiB"),
])
def test_decoded_oversized_dictionary_key_rejected_before_utf8_encoding(
    key_size, expected, monkeypatch
):
    from repocache import server_install_v1

    source = {("k" * key_size): "untrusted", **document()}
    original = server_install_v1._string

    def only_encode_bounded_field_names(value, name, **kwargs):
        if name == "JSON field name":
            assert len(value) <= 2048, "oversized key reached UTF-8 encoding"
        return original(value, name, **kwargs)

    monkeypatch.setattr(server_install_v1, "_string", only_encode_bounded_field_names)
    with pytest.raises(InstallInputError, match=expected):
        validate_install_document(source)


def test_non_string_dictionary_key_is_rejected_before_encoding():
    source = {123: "untrusted", **document()}
    with pytest.raises(InstallInputError, match="JSON field name: expected string"):
        validate_install_document(source)


def test_exact_compact_json_byte_cap_including_unicode():
    from repocache.server_install_v1 import _depth, _predecoded_size

    # These direct-object boundary tests exercise the budget and the exact
    # compact JSON encoder independently of the closed install schema.
    maximum_ascii = "x" * (MAX_DOCUMENT_BYTES - 2)
    _depth(maximum_ascii)
    _predecoded_size(maximum_ascii)
    with pytest.raises(InstallInputError, match="exceeds 1 MiB"):
        _predecoded_size(maximum_ascii + "x")

    # Two UTF-8 bytes per code point: 2 quotes and exactly 1 MiB payload.
    maximum_utf8 = "á" * ((MAX_DOCUMENT_BYTES - 2) // 2)
    _depth(maximum_utf8)
    _predecoded_size(maximum_utf8)
    with pytest.raises(InstallInputError, match="exceeds 1 MiB"):
        _predecoded_size(maximum_utf8 + "á")


@pytest.mark.parametrize("field,new_value", [
    ("releasever", "11"),
    ("basearch", "aarch64"),
    ("metadata_path", "repodata/other.xml"),
])
def test_dnf_routing_field_change_is_a_distinct_identity(field, new_value):
    source = document()
    dnf = next(item for item in source["repositories"] if item["kind"] == "dnf")
    proposed = copy.deepcopy(dnf)
    proposed["id"] = "another-dnf"
    proposed["layout"][field] = new_value
    source["repositories"].append(proposed)
    assert len(validate_install_document(source)["repositories"]) == 3
