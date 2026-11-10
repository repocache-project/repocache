"""Disposable exact-five-PR lifecycle + fixed shadow WAL integration (#31).

This script needs the *locally merged* PR #237/#252/#251/#254/#214 sources
in the CI throwaway container. It performs real distro nginx -T syntax,
but NO root helper, native systemd, production NGINX, public catalog
publication or operator authorization. The protected-root fixture is private.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile

from ci_v06_cross_pr_lifecycle_contract import (
    _CA, canonical_bytes, state, syntax_checked_candidate,
)
from repocache.server_fixture_multi_resource_wal_v1 import (
    CATALOG, INCLUDE, JOURNAL, JOURNAL_TMP, MANIFEST, ORDER, STAGE,
    _commit_fixture_multi_resource_under_root as commit,
    _recover_fixture_multi_resource_under_root as recover,
)
from repocache.server_nginx_repository_bundle_v1 import (
    render_repository_nginx_bundle_candidate,
)
from repocache.server_proposed_state_v2_store import V2_STATE
from repocache.server_protected_state_store_v1 import LOCK_NAME
from repocache.server_repository_reconcile_v1 import (
    preview_repository_lifecycle_nginx_from_untrusted_document,
)


def _catalog(ids: list[str]) -> bytes:
    return canonical_bytes({
        "schema_version": 1,
        "status": "fixture-only-observed-candidate",
        "active_ids": ids,
    })


def _stage(document: dict, pins: dict, root: Path) -> tuple[bytes, bytes]:
    """Independently derive NGINX bytes and verify #251 client schema hints.

    The source is the exact proposed declarative document, NOT the proxy's
    live service. The dump and candidate may not imply actual exposure.
    """
    bundle = render_repository_nginx_bundle_candidate(
        document,
        expected_state_generation=document["expected_state_generation"],
        candidate_pins_by_repository=pins,
        ca_bundle_path=_CA,
    )
    catalog = syntax_checked_candidate(document, pins, root)
    expected_ids = bundle["proposed_repository_ids"]
    assert catalog["desired_active_repository_ids"] == expected_ids
    assert len(catalog["candidate_catalog"]["repositories"]) == len(expected_ids)
    assert catalog["inert_nginx_dump_routes_match_candidate"] is True
    for key in (
        "actual_active_exposure_verified", "installed_catalog_publication_verified",
        "authorizes_nginx_reload", "authorizes_catalog_publication",
    ):
        assert catalog[key] is False
    assert bundle["authorizes_nginx_activation"] is False
    assert bundle["authorizes_catalog_publication"] is False
    include = (
        "# fixture ONLY, not an installed nginx include\n"
        + bundle["http_upstream_fragment"]
        + bundle["server_location_fragment"]
    ).encode("utf-8")
    return include, _catalog(expected_ids)


def _snapshot_bytes(folder: Path) -> dict[str, bytes]:
    return {name: (folder / name).read_bytes() for name in ORDER}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="repocache-five-pr-multi-wal-") as temp:
        base = Path(temp)
        root = base / "fixture-root"
        root.mkdir(mode=0o700)
        folder = root
        for name in ("var", "lib", "repocache", "server"):
            folder = folder / name
            folder.mkdir(mode=0o700)
        (folder / LOCK_NAME).write_bytes(b"")
        (folder / LOCK_NAME).chmod(0o600)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        uid = os.geteuid()
        try:
            doc = json.loads(Path(
                "docs/examples/server-install-v1.json"
            ).read_text(encoding="utf-8"))
            doc["repositories"][1]["id"] = "almalinux-baseos"
            for row in doc["repositories"]:
                row["desired_state"] = "disabled"
            doc["expected_state_generation"] = 1
            initial = state(doc, generation=1, previous=None)
            include, catalog = _stage(doc, {}, base)
            result = commit(
                fd, initial, owner_uid=uid, expected_generation=0,
                include_bytes=include, catalog_bytes=catalog,
            )
            assert result["status"] == "COMMITTED_INERT_FIXTURE_MULTI_RESOURCE"
            assert result["host_activation_verified"] is False
            assert json.loads((folder / CATALOG).read_bytes())["active_ids"] == []

            current = doc
            previous = initial
            chosen = current["repositories"][0]["id"]
            host = current["repositories"][0]["upstream"]["allowed_hosts"][0]
            pins = {chosen: {host: ["8.8.8.8"]}}
            actions = (
                ("enable", pins),
                ("disable", {}),
                ("remove", {}),
            )
            for index, (operation, candidate_pins) in enumerate(actions, 2):
                plan = preview_repository_lifecycle_nginx_from_untrusted_document(
                    current, current_generation=index - 1,
                    operation=operation, repository_id=chosen,
                    candidate_pins_by_repository=candidate_pins,
                    ca_bundle_path=_CA,
                )
                new_doc = copy.deepcopy(
                    plan["next_generation_configuration_preview"]
                )
                assert new_doc["expected_state_generation"] == index
                proposed = state(
                    new_doc, generation=index, previous=previous,
                )
                new_include, new_catalog = _stage(new_doc, candidate_pins, base)
                old_bytes = _snapshot_bytes(folder)
                observed = []

                def before_cleanup() -> None:
                    # The held lock and persistent WAL cover the shadow
                    # state, NGINX and derived catalog when this callback runs.
                    assert (folder / JOURNAL).is_file()
                    assert (folder / V2_STATE).read_bytes() == canonical_bytes(proposed)
                    assert (folder / INCLUDE).read_bytes() == new_include
                    assert (folder / CATALOG).read_bytes() == new_catalog
                    assert (folder / MANIFEST).is_file()
                    observed.append("fixture-barrier")
                    return None

                if operation == "enable":
                    # A real child process exits abruptly after the shadow
                    # NGINX/state/catalog replacements; a *different process*
                    # must reacquire the pinned lock and restore the old
                    # generation. No fixture cleanup callback may execute.
                    pid = os.fork()
                    if pid == 0:
                        try:
                            def crash(point: str) -> None:
                                if point == "catalog_durable":
                                    os._exit(41)

                            commit(
                                fd, proposed, owner_uid=uid,
                                expected_generation=index - 1,
                                include_bytes=new_include,
                                catalog_bytes=new_catalog,
                                inject_fault=crash,
                            )
                        except BaseException:
                            os._exit(71)
                        os._exit(72)
                    ended, status = os.waitpid(pid, 0)
                    assert ended == pid
                    assert os.waitstatus_to_exitcode(status) == 41
                    assert (folder / JOURNAL).is_file()
                    recovered = recover(fd, owner_uid=uid)
                    assert recovered["status"] == (
                        "ROLLED_BACK_INERT_FIXTURE_MULTI_RESOURCE"
                    )
                    assert _snapshot_bytes(folder) == old_bytes
                    assert recover(fd, owner_uid=uid)["status"] == (
                        "CLEAN_INERT_FIXTURE"
                    )

                def verify_before_catalog() -> None:
                    # A proposed mapping must not enter even the inert
                    # fixture catalog before the durable candidate is checked.
                    assert (folder / JOURNAL).is_file()
                    assert (folder / INCLUDE).read_bytes() == new_include
                    assert (folder / V2_STATE).read_bytes() == canonical_bytes(proposed)
                    assert (folder / CATALOG).read_bytes() == old_bytes[CATALOG]
                    assert (folder / MANIFEST).read_bytes() == old_bytes[MANIFEST]
                    # Repeat the real packaged NGINX -T + derived client
                    # catalog candidate check WHILE this same fixture WAL
                    # and FD lock remain held; the earlier staging check
                    # is not a reusable authority or generation lease.
                    rechecked = syntax_checked_candidate(
                        new_doc, candidate_pins, base,
                    )
                    assert rechecked["desired_active_repository_ids"] == (
                        [chosen] if operation == "enable" else []
                    )
                    assert rechecked["actual_active_exposure_verified"] is False
                    assert (folder / CATALOG).read_bytes() == old_bytes[CATALOG]
                    observed.append("before-fixture-catalog")
                    return None

                report = commit(
                    fd, proposed, owner_uid=uid,
                    expected_generation=index - 1,
                    include_bytes=new_include, catalog_bytes=new_catalog,
                    verify_fixture_exposure_before_publish=verify_before_catalog,
                    verify_fixture_effects=before_cleanup,
                )
                assert report["state_generation"] == index
                assert observed == ["before-fixture-catalog", "fixture-barrier"]
                assert report["prepublication_fixture_barrier_executed"] is True
                assert all(not (folder / name).exists()
                           for name in (JOURNAL, JOURNAL_TMP, STAGE))
                assert report["authorizes_nginx_reload"] is False
                assert report["authorizes_catalog_publication"] is False
                assert json.loads((folder / CATALOG).read_bytes())["active_ids"] == (
                    [chosen] if operation == "enable" else []
                )
                current, previous = new_doc, proposed

            retired = {entry["id"]: entry for entry in previous["id_reservations"]}
            assert retired[chosen]["status"] == "retired"
            assert chosen not in {
                record["id"] for record in previous["repository_records"]
            }
            assert recover(fd, owner_uid=uid)["status"] == "CLEAN_INERT_FIXTURE"
            print(
                "PASS: five-PR combined #95 lifecycle, #28 actual native nginx -T, "
                "#251 derived active-only candidate, #31 durable shadow WAL "
                "and real-PID interrupted enable/recovery/retry; never activated host "
                "service or published client catalog"
            )
        finally:
            os.close(fd)


if __name__ == "__main__":
    main()
