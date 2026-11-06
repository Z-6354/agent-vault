"""Synthetic local acceptance through the same core transport as real MCP.
Remote browser/stdio integration is covered by tests/test_broker.py.
"""
from pathlib import Path
import json
import sys
import threading

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from agent_vault.broker import Broker
from agent_vault.ipc import CoreClient
from agent_vault.mcp_server import McpServer
from agent_vault.mock import HITS, start_mock
from helpers import cleanup, test_directory

PASSWORD = "synthetic-acceptance-passphrase"
SECRET = "synthetic_token_acceptance"
ADMIN = {"owner_id": "local", "principal_id": "admin", "client_id": "management"}
AUTH = {"owner_id": "local", "principal_id": "agent:acceptance", "client_id": "execution"}


def main():
    root = test_directory("acceptance-")
    mock = start_mock()
    mock_thread = threading.Thread(target=mock.serve_forever, daemon=True)
    mock_thread.start()
    broker = None
    server = None
    thread = None
    passed = 0
    def check(label, condition):
        nonlocal passed
        if not condition:
            raise AssertionError(label)
        passed += 1
        print("PASS " + label)
    def start():
        nonlocal broker, server, thread
        broker = Broker(root + "/data", 0)
        server = broker.build_server()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return CoreClient(root + "/data", broker.port)
    def stop():
        server.shutdown()
        server.server_close()
        thread.join(3)
        broker.core.close()
    try:
        HITS.clear()
        client = start()
        client.call_tool("vault_select_target", {"mode": "local"}, AUTH)
        check("selection does not create database", not Path(root, "data", "vault.sqlite").exists())
        client.command("create", {"selection_id": client.command("status", {})["selection_id"],
                                  "passphrase": PASSWORD, "confirm": PASSWORD, "remember_device": False})
        check("same core reports connected", client.command("status", {})["connected"])
        client.command("manage", {"method": "grant", "agent_id": "acceptance", "operations": ["mock.account_summary"]})
        # Trusted management fixture creates an executable synthetic credential.
        vault = broker.core.active
        payload = {"mode": "create", "label": "acceptance", "service_id": "synthetic-mock",
            "credential_type": "api_key", "account_alias": "acceptance", "secret": SECRET,
            "origin": "http://127.0.0.1:43121", "environment": "local",
            "granted_operations": ["mock.account_summary"]}
        draft = vault.create_draft(ADMIN, payload)
        approval = vault.approve_draft(ADMIN, draft["draft_id"], 1)
        saved = vault.save_approved(ADMIN, {"request_id": "a"*32, "draft_id": draft["draft_id"],
            "draft_version": 1, "approval_token": approval["approval_token"], "payload": payload})
        mcp = McpServer(client, agent_id="acceptance")
        def call(name, args):
            return json.loads(mcp.call_tool(name, args)["content"][0]["text"])
        ticket = call("prepare_request", {"operation_name": "mock.account_summary"})
        args = {"request_id": ticket["request_id"], "connection_id": saved["connection_id"],
                "operation_id": "mock.account_summary", "expected_record_version": 1}
        result = call("execute_operation", args)
        check("MCP executes through shared core", result["operation"]["state"] == "succeeded")
        check("one upstream dispatch", len(HITS) == 1)
        check("secret absent from model result", SECRET not in json.dumps(result))
        stop()
        client = start()
        mcp = McpServer(client, agent_id="acceptance")
        check("opt-out restart requires authentication",  call("execute_operation", args)["error"] == "login_required")
        client.command("login", {"selection_id": client.command("status", {})["selection_id"],
                                 "passphrase": PASSWORD})
        check("authenticated restart replays durable result", call("execute_operation", args) == result)
        check("replay never redispatches", len(HITS) == 1)
        client.command("logout", {})
        check("logout disables tools", call("vault_list", {})["error"] == "login_required")
        print(f"ACCEPTANCE OK ({passed} invariants)")
        return 0
    finally:
        if server:
            stop()
        mock.shutdown()
        mock.server_close()
        mock_thread.join(3)
        cleanup(root)


if __name__ == "__main__":
    raise SystemExit(main())
