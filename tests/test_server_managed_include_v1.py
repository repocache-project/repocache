"""Pure managed-include drift-refusal preview tests; no native/NGINX acceptance."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from repocache.server_managed_include_v1 import (
    MAX_CANDIDATE_BYTES,
    ManagedIncludePreviewError,
    preview_managed_include,
)

EXAMPLE = Path(__file__).resolve().parents[1] / "docs/examples/server-install-v1.json"
FIRST = b"# controlled NGINX candidate one\n"
NEXT = b"# controlled NGINX candidate two\n"


def document(generation=2):
    result = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    result["expected_state_generation"] = generation
    return result


def manifest(doc, data=FIRST):
    return {
        "schema_version": 1,
        "generation": 1,
        "path": doc["deployment"]["paths"]["generated_include"],
        "sha256": hashlib.sha256(data).hexdigest(),
        "uid": 0,
        "gid": 33,
        "mode": 0o640,
        "dev": 10,
        "ino": 21,
    }


def observed(entry):
    return {
        "path": entry["path"],
        "kind": "regular",
        "sha256": entry["sha256"],
        "uid": entry["uid"],
        "gid": entry["gid"],
        "mode": entry["mode"],
        "dev": entry["dev"],
        "ino": entry["ino"],
        "nlink": 1,
    }


def review(doc=None, *, data=NEXT, previous=None, actual=None, generation=2):
    doc = document() if doc is None else doc
    return preview_managed_include(
        doc,
        current_generation=generation,
        candidate_bytes=data,
        previous_manifest=previous,
        observed_file=actual,
    )


def test_clean_create_preview_never_authorizes_activation():
    result = review(previous=None, actual=None)
    assert result == {
        "schema_version": 1,
        "status": "PREVIEW_ONLY",
        "action": "WOULD_CREATE",
        "changed": True,
        "current_generation": 2,
        "authorizes_write": False,
        "authorizes_nginx_reload": False,
        "authorizes_catalog_publication": False,
        "protected_manifest_provenance_verified": False,
        "live_filesystem_ownership_verified": False,
        "nginx_syntax_verified": False,
    }


def test_repeat_preview_is_idempotent_without_generation_increment():
    doc = document()
    previous = manifest(doc)
    actual = observed(previous)
    old_doc, old_previous, old_actual = (
        copy.deepcopy(doc), copy.deepcopy(previous), copy.deepcopy(actual)
    )
    for _ in range(3):
        result = review(doc, data=FIRST, previous=previous, actual=actual)
        assert result["action"] == "UNCHANGED"
        assert result["changed"] is False
        assert result["current_generation"] == 2
        assert result["authorizes_write"] is False
    assert doc == old_doc and previous == old_previous and actual == old_actual


def test_different_candidate_requires_future_authorized_staging():
    doc = document()
    previous = manifest(doc)
    result = review(doc, previous=previous, actual=observed(previous))
    assert result["action"] == "WOULD_REPLACE"
    assert result["nginx_syntax_verified"] is False
    assert result["live_filesystem_ownership_verified"] is False


def test_foreign_existing_include_never_adopted_even_if_identical():
    doc = document()
    actual = observed(manifest(doc, NEXT))
    with pytest.raises(ManagedIncludePreviewError, match="FOREIGN_INCLUDE_REFUSED"):
        review(doc, data=NEXT, previous=None, actual=actual)


def test_missing_manifested_include_never_silently_recreated():
    doc = document()
    with pytest.raises(ManagedIncludePreviewError, match="MANAGED_INCLUDE_MISSING"):
        review(doc, previous=manifest(doc), actual=None)


@pytest.mark.parametrize(("changed", "value", "expected_code"), [
    ("sha256", "0" * 64, "MANAGED_INCLUDE_DRIFT"),
    ("uid", 1000, "MANAGED_INCLUDE_UNSAFE_METADATA"),
    ("gid", 1001, "MANAGED_INCLUDE_DRIFT"),
    ("mode", 0o666, "MANAGED_INCLUDE_UNSAFE_METADATA"),
    ("mode", 0o600, "MANAGED_INCLUDE_DRIFT"),
    ("dev", 20, "MANAGED_INCLUDE_DRIFT"),
    ("ino", 22, "MANAGED_INCLUDE_DRIFT"),
    ("nlink", 2, "MANAGED_INCLUDE_HARDLINK_OR_UNKNOWN"),
    ("kind", "symlink", "MANAGED_INCLUDE_NOT_REGULAR"),
    ("path", "/etc/nginx/conf.d/foreign.conf", "MANAGED_INCLUDE_PATH_MISMATCH"),
])
def test_observed_drift_or_unsafe_metadata_refused(changed, value, expected_code):
    doc = document()
    previous = manifest(doc)
    actual = observed(previous)
    actual[changed] = value
    with pytest.raises(ManagedIncludePreviewError, match=expected_code):
        review(doc, previous=previous, actual=actual)


@pytest.mark.parametrize(("field", "value"), [
    ("uid", True), ("uid", -1), ("gid", -1), ("mode", True),
    ("mode", 0o4755), ("dev", 0), ("ino", 0),
    ("sha256", "A" * 64), ("sha256", "malformed"),
    ("generation", 0), ("generation", True), ("schema_version", 2),
])
def test_malformed_manifest_is_rejected(field, value):
    doc = document()
    previous = manifest(doc)
    previous[field] = value
    with pytest.raises(ManagedIncludePreviewError):
        review(doc, previous=previous, actual=observed(manifest(doc)))


def test_future_generation_and_stale_generation_refused():
    doc = document()
    previous = manifest(doc)
    previous["generation"] = 3
    with pytest.raises(ManagedIncludePreviewError, match="MANIFEST_GENERATION_AHEAD"):
        review(doc, previous=previous, actual=observed(manifest(doc)))
    with pytest.raises(ManagedIncludePreviewError, match="STALE_STATE_GENERATION"):
        review(doc, generation=3, previous=manifest(doc), actual=observed(manifest(doc)))
    with pytest.raises(ManagedIncludePreviewError, match="CURRENT_GENERATION_INVALID"):
        review(doc, generation=True)


@pytest.mark.parametrize("field", ["schema_version", "path", "sha256", "uid"])
def test_missing_manifest_field_is_refused(field):
    doc = document()
    previous = manifest(doc)
    actual = observed(previous)
    del previous[field]
    with pytest.raises(ManagedIncludePreviewError, match="MANIFEST_OR_OBSERVATION_SCHEMA_INVALID"):
        review(doc, previous=previous, actual=actual)


def test_unknown_manifest_and_observation_fields_fail_closed():
    doc = document()
    previous = manifest(doc)
    actual = observed(previous)
    previous["approved"] = True
    with pytest.raises(ManagedIncludePreviewError, match="MANIFEST_OR_OBSERVATION_SCHEMA_INVALID"):
        review(doc, previous=previous, actual=actual)
    del previous["approved"]
    actual["trusted"] = True
    with pytest.raises(ManagedIncludePreviewError, match="MANIFEST_OR_OBSERVATION_SCHEMA_INVALID"):
        review(doc, previous=previous, actual=actual)


@pytest.mark.parametrize("bad", [
    b"", b"\x00", b"not valid\xffutf8", b"a" * (MAX_CANDIDATE_BYTES + 1),
    "nginx config is not bytes", bytearray(b"config"),
])
def test_invalid_candidate_rejected_without_echoing_input(bad):
    with pytest.raises(ManagedIncludePreviewError) as exc:
        review(data=bad)
    assert "config" not in str(exc.value) and "nginx" not in str(exc.value)


def test_no_host_access_or_external_side_effects(monkeypatch, tmp_path):
    import os
    import socket
    import subprocess

    def forbidden(*_a, **_kw):
        raise AssertionError("Preview attempted a forbidden external operation")

    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    doc = document()
    previous = manifest(doc)
    report = review(doc, previous=previous, actual=observed(previous))
    assert report["action"] == "WOULD_REPLACE"
    assert list(tmp_path.iterdir()) == []


def test_no_path_or_secret_data_in_diagnostics():
    doc = document()
    previous = manifest(doc)
    previous["path"] = "/etc/private/secret-token"
    with pytest.raises(ManagedIncludePreviewError) as exc:
        review(doc, previous=previous, actual=observed(manifest(doc)))
    assert "secret-token" not in str(exc.value)
    assert "/etc/" not in str(exc.value)
