"""Adversarial, read-only coverage for dependency graph preview (#81)."""
from __future__ import annotations

import hashlib
import zipfile

import pytest
from pip._vendor.packaging.requirements import Requirement
from scripts.ci_dependency_graph_v05 import (
    GraphRefused, check_monitor, metadata_from_wheel, parse_lock, resolve,
)


SHA = "a" * 64


def requirements(**rows):
    return {name: [Requirement(s) for s in lines] for name, lines in rows.items()}


def test_lock_and_monitor_exact_identity():
    expected = parse_lock("typer 0.27.3 " + SHA + "\n" +
                          "rich 15.0.0 " + "b" * 64 + "\n")
    check_monitor("# Monitoring only\ntyper==0.27.3 --hash=sha256:" +
                  SHA + "\nrich==15.0.0 --hash=sha256:" + "b" * 64 + "\n", expected)
    with pytest.raises(GraphRefused, match="match reviewed lock"):
        check_monitor("typer==0.27.4 --hash=sha256:" + SHA +
                      "\nrich==15.0.0 --hash=sha256:" + "b" * 64 + "\n", expected)


@pytest.mark.parametrize("bad", [
    "typer 0.27.3 " + SHA,
    "Typer 0.27.3 " + SHA + "\n",
    "typer 0.27.3 " + SHA + "\ntyper 0.27.3 " + SHA + "\n",
    "typer 0.27.3 " + "Z" * 64 + "\n",
    "--index-url https://unsafe.invalid\n",
])
def test_bad_source_locks_fail_closed(bad):
    with pytest.raises(GraphRefused):
        parse_lock(bad)


def test_real_parent_child_edges_and_requested_extra():
    rows = {
        "root": ("1.0.0", SHA),
        "parser": ("2.0.0", SHA),
        "linkify": ("3.0.0", SHA),
        "leaf": ("4.0.0", SHA),
    }
    metadata = requirements(
        root=["parser[link] >=2; python_version >= '3.12'", "leaf==4.0.0"],
        parser=["linkify>=3; extra == 'link'"],
        linkify=[],
        leaf=[],
    )
    graph = resolve(rows, metadata, {"root"}, {"python_version": "3.13",
                                                   "sys_platform": "linux"})
    assert graph["root"]["relationship"] == "direct"
    assert {n for n in graph if graph[n]["relationship"] == "indirect"} == {
        "parser", "linkify", "leaf"
    }
    assert graph["root"]["dependencies"] == [
        "pkg:pypi/leaf@4.0.0", "pkg:pypi/parser@2.0.0"
    ]
    assert graph["parser"]["dependencies"] == ["pkg:pypi/linkify@3.0.0"]


def test_environment_marker_skips_foreign_platform():
    rows = {"root": ("1.0.0", SHA), "leaf": ("1.0.0", SHA)}
    metadata = requirements(root=["leaf==1.0.0; sys_platform == 'linux'"],
                            leaf=[])
    assert resolve(rows, metadata, {"root"}, {"sys_platform": "linux"})[
        "leaf"]["relationship"] == "indirect"
    with pytest.raises(GraphRefused, match="Unreachable"):
        resolve(rows, metadata, {"root"}, {"sys_platform": "win32"})


@pytest.mark.parametrize("child", ["unexpected>=1", "leaf>=9",
                                   "leaf @ https://bad.invalid/wheel.whl"])
def test_out_of_lock_unknown_or_incompatible_requirement_is_rejected(child):
    rows = {"root": ("1.0.0", SHA), "leaf": ("1.0.0", SHA)}
    with pytest.raises(GraphRefused):
        resolve(rows, requirements(root=[child], leaf=[]),
                {"root"}, {"sys_platform": "linux"})


def test_missing_metadata_or_orphan_rejected():
    rows = {"root": ("1.0.0", SHA), "leaf": ("1.0.0", SHA)}
    with pytest.raises(GraphRefused, match="Missing pinned"):
        resolve(rows, requirements(root=[]), {"root"}, {})
    with pytest.raises(GraphRefused, match="Unreachable"):
        resolve(rows, requirements(root=[], leaf=[]), {"root"}, {})


def test_extras_do_not_activate_without_request():
    rows = {"root": ("1.0.0", SHA), "child": ("1.0.0", SHA)}
    metadata = requirements(root=["child==1.0.0"], child=[])
    graph = resolve(rows, metadata, {"root"}, {"python_version": "3.13"})
    assert graph["child"]["relationship"] == "indirect"


def _wheel(tmp_path, metadata: bytes):
    path = tmp_path / "pkg-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("pkg-1.0.0.dist-info/METADATA", metadata)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_verified_wheel_metadata_is_parsed_without_package_execution(tmp_path):
    wheel, digest = _wheel(tmp_path, b"Name: pkg\nVersion: 1.0.0\n"
                                     b"Requires-Dist: child>=2\n\n")
    parsed = metadata_from_wheel(wheel, "pkg", "1.0.0", digest)
    assert len(parsed) == 1 and parsed[0].name == "child"
    with pytest.raises(GraphRefused, match="digest"):
        metadata_from_wheel(wheel, "pkg", "1.0.0", "0" * 64)
    with pytest.raises(GraphRefused, match="identity"):
        metadata_from_wheel(wheel, "wrong", "1.0.0", digest)


def test_bad_wheel_metadata_refused(tmp_path):
    wheel, digest = _wheel(tmp_path, b"Name: pkg\nVersion: 1.0.0\n"
                                     b"Requires-Dist: invalid >>> 3\n\n")
    with pytest.raises(GraphRefused, match="Requires-Dist"):
        metadata_from_wheel(wheel, "pkg", "1.0.0", digest)
