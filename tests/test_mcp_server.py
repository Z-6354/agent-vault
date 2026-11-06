"""MCP wire contract tests. HTTP/browser/real stdio coverage is in test_broker."""
import json
import unittest

from agent_vault.errors import VaultError
from agent_vault.mcp_server import McpServer, TOOLS


class SafeTransport:
    url = "http://127.0.0.1:43122"
    def call_tool(self, name, arguments, auth):
        if name == "vault_status":
            return {"phase": "needs_target", "connected": False}
        raise VaultError(401, "login_required")


class McpServerTests(unittest.TestCase):
    def setUp(self):
        self.server = McpServer(SafeTransport(), agent_id="test")

    def test_protocol_shapes(self):
        def rpc(method, params=None):
            return self.server.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
        self.assertEqual(rpc("initialize")["result"]["serverInfo"]["name"], "agent-vault")
        self.assertEqual(rpc("ping")["result"], {})
        self.assertEqual(len(rpc("tools/list")["result"]["tools"]), len(TOOLS))
        self.assertEqual(rpc("no/such")["error"]["code"], -32601)
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        for tool in TOOLS:
            self.assertFalse({"password", "secret", "token", "api_key"} & set(tool["inputSchema"]["properties"]))

    def test_rejects_extra_keys_types_and_non_objects_without_echo(self):
        for name, args in [("no_such_tool", {}), ("vault_status", {"password": "synthetic-canary"}),
                           ("vault_find", {"service_id": []}), ([], {}),
                           ("vault_begin_enrollment", {"service": "x"}), ("vault_status", [])]:
            result = self.server.call_tool(name, args)
            self.assertTrue(result["isError"])
            self.assertNotIn("synthetic-canary", json.dumps(result))
        self.assertEqual(self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []})["error"]["code"], -32602)

    def test_status_links_to_core_and_failed_login_is_safe(self):
        result = json.loads(self.server.call_tool("vault_status", {})["content"][0]["text"])
        self.assertEqual(result["card_url"], SafeTransport.url + "/")
        self.assertFalse(result["connected"])
        result = self.server.call_tool("vault_list", {})
        self.assertTrue(result["isError"])
        self.assertEqual(json.loads(result["content"][0]["text"])["error"], "login_required")


if __name__ == "__main__":
    unittest.main()
