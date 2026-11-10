"""Distro-container negative: refuse native VM authority without a booted host."""
from __future__ import annotations

import json
import os

from repocache.server_native_vm_readonly_v1 import (
    inspect_booted_vm_nginx_readonly,
)


def main() -> int:
    # Only existing disposable distro test images call this script.
    if not os.path.lexists("/.dockerenv"):
        print('{"status":"FAIL","code":"NOT_IN_DISPOSABLE_DOCKER"}')
        return 1
    result = inspect_booted_vm_nginx_readonly()
    if (result["status"] != "NOT VERIFIED"
            or result["code"] != "CONTAINER_CONTEXT_REFUSED"
            or result["complete_server_acceptance_passed"] is not False
            or result["authorizes_host_write"] is not False
            or result["authorizes_nginx_reload"] is not False):
        print('{"status":"FAIL","code":"NATIVE_VM_FALSE_POSITIVE"}')
        return 1
    print(json.dumps({
        "status": "PASS", "code": "DOCKER_REFUSED_AS_BOOTED_VM",
        "native_vm_acceptance": "NOT VERIFIED",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
