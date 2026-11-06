"""Show the allowed operations of a stored credential (metadata only)."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src")]

from agent_vault.ipc import CoreClient  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", default="magpie")
    parser.add_argument("--account", default="dsh")
    parser.add_argument("--data-dir", default=os.environ.get("AGENT_VAULT_DATA_DIR", os.path.expanduser("~/.agent-vault")))
    parser.add_argument("--port", type=int, default=int(os.environ.get("AGENT_VAULT_BROKER_PORT", "43122")))
    args = parser.parse_args()
    client = CoreClient(args.data_dir, args.port)
    listing = client.call_tool("vault_list", {}, {"owner_id": "local",
        "principal_id": "agent:magpie-check", "client_id": "execution"})
    matches = [row for row in listing.get("connections", [])
               if row.get("service_id") == args.service and row.get("account_alias") == args.account]
    if not matches:
        print(json.dumps({"error": "not_found", "service": args.service, "account": args.account}))
        return 1
    connection_id = matches[0]["connection_id"]
    try:
        scope = client.command("consume", {"connection_id": connection_id, "scope_only": True})
    except Exception as error:
        print(json.dumps({"error": type(error).__name__, "detail": str(error)[:200]}))
        return 2
    print(json.dumps({"service": args.service, "account": args.account,
                      "connection_id": connection_id, "scope": scope}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
