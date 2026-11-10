"""Read-only VM readiness observation; no installation or service control."""
from __future__ import annotations

import json
import sys
from repocache.server_native_vm_readonly_v1 import (
    inspect_booted_vm_nginx_readonly,
)


def main() -> int:
    if len(sys.argv) != 1:
        print('{"code":"ARGUMENTS_REFUSED","status":"NOT VERIFIED"}')
        return 2
    result = inspect_booted_vm_nginx_readonly()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # Exit 0 means only the named read-only prerequisites were observable.
    # It never certifies complete server installation or service authority.
    return 0 if result["effective_nginx_master_observed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
