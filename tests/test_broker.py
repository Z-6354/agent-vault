"""Real HTTP/stdio boundary tests; synthetic remote service, no production writes."""
import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import unittest
import urllib.error
import urllib.request
import uuid

from agent_vault.broker import Broker, ensure_running
from agent_vault.ipc import CoreClient
from agent_vault.mcp_server import McpServer
from agent_vault.errors import VaultError
from helpers import cleanup, test_directory

PASSWORD = "synthetic-login-password"
SECRET = "synthetic-secret-canary-not-for-model"
TOKEN = "synthetic-session-canary-not-for-model"
AUTH = {"owner_id": "local", "principal_id": "agent:test", "client_id": "execution"}


class RemoteFixture:
    def __init__(self):
        self.rows = []
        self.writes = 0
        self.mode = "existing"
        self.unauthorized = False
        self.password = PASSWORD
        self.token = TOKEN
        self.login_count = 0
        self.unavailable = False
        self.forbidden = False
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def send(self, code, value):
                body = json.dumps(value).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def do_GET(self):
                if fixture.unavailable:
                    self.send(503, {})
                    return
                if fixture.forbidden:
                    self.send(403, {})
                    return
                if self.path == "/openapi.json":
                    paths = {key: {} for key in ("/api/v1/auth/login", "/api/v1/auth/status", "/api/v1/credentials")}
                    if fixture.mode.startswith("uninitialized"):
                        paths["/api/v1/setup/status"] = {"get": {}}
                    self.send(200, {"paths": paths})
                elif self.path == "/api/v1/setup/status":
                    self.send(200, {"initialized": False})
                elif fixture.unauthorized or self.headers.get("Authorization") != "Bearer " + fixture.token:
                    self.send(401, {"secret": SECRET, "password": PASSWORD})
                elif self.path == "/api/v1/auth/status":
                    self.send(200, {"status": "connected"})
                elif self.path == "/api/v1/credentials/list":
                    self.send(200, fixture.rows)
                else:
                    self.send(404, {})
            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if fixture.unavailable:
                    self.send(503, {})
                    return
                if self.path == "/api/v1/auth/login":
                    fixture.login_count += 1
                    if data.get("password") != fixture.password:
                        self.send(401, {"password": data.get("password")})
                    else:
                        self.send(200, {"token": fixture.token})
                elif self.path == "/api/v1/credentials/resolve":
                    row = next((r for r in fixture.rows
                                if r["connection_id"] == data.get("connection_id")), None)
                    if row:
                        self.send(200, {"candidate": row})
                    else:
                        self.send(404, {})
                elif self.path == "/api/v1/credentials/consume":
                    row = next((r for r in fixture.rows
                                if r["connection_id"] == data.get("connection_id")), None)
                    if row and data.get("operation") in (row.get("allowed_operations") or []):
                        self.send(200, {"status": "granted", "connection_id": row["connection_id"],
                                        "service_id": row["service_id"], "secret": row["secret"]})
                    else:
                        self.send(403, {})
                elif self.path == "/api/v1/credentials":
                    if self.headers.get("Authorization") != "Bearer " + fixture.token:
                        self.send(401, {})
                        return
                    fixture.writes += 1
                    row = {"connection_id": str(uuid.uuid4()), **data}
                    fixture.rows.append(row)
                    if fixture.mode == "uncertain":
                        self.send(502, {"secret": SECRET})
                    else:
                        self.send(200, {"status": "saved", "connection_id": row["connection_id"], "secret": SECRET})
                else:
                    self.send(404, {})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_port)
    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.root = test_directory("unified-core-")
        self.addCleanup(cleanup, self.root)
        self.remote = RemoteFixture()
        self.addCleanup(self.remote.close)
        self.directory = self.root + "/data"
        self.broker = Broker(self.directory, 0, allow_loopback_http=True)
        self.server = self.broker.build_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_broker)
        self.client = CoreClient(self.directory, self.broker.port)
        self.mcp = McpServer(self.client, agent_id="test")
        self.base = self.client.url
        self.jar = http.cookiejar.CookieJar()
        self.browser = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.jar))
        _, body = self.fetch("/")
        self.csrf = re.search(r'name="vault-csrf" content="([^"]+)"', body).group(1)

    def close_broker(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.broker.core.logout()

    def fetch(self, path, data=None, extra=None):
        request = urllib.request.Request(self.base + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Content-Type": "application/json", "X-Vault-CSRF": getattr(self, "csrf", ""),
                     "Origin": self.base, **(extra or {})})
        try:
            response = self.browser.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.code, response.read().decode()

    def post(self, path, data):
        if path in ("/api/login", "/api/create"):
            data = {"selection_id": self.call("vault_status")["selection_id"], **data}
        code, body = self.fetch(path, data)
        return code, json.loads(body)

    def call(self, name, args=None):
        result = self.mcp.call_tool(name, args or {})
        body = json.loads(result["content"][0]["text"])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn(TOKEN, json.dumps(result))
        self.assertNotIn(PASSWORD, json.dumps(result))
        return body

    def remote_login(self, remember=True):
        result = self.call("vault_select_target", {"mode": "remote", "server_url": self.remote.url})
        self.assertEqual(result["phase"], "needs_login")
        self.assertEqual(self.post("/api/login", {"username": "synthetic-user", "passphrase": PASSWORD,
                                                   "remember_device": remember})[0], 200)

    def test_browser_login_and_stdio_share_single_remote_session(self):
        self.assertEqual(self.call("vault_status")["phase"], "needs_target")
        self.remote_login()
        # Real stdio entry uses the already running service, no second Vault.
        env = dict(os.environ, AGENT_VAULT_DATA_DIR=self.directory,
                   AGENT_VAULT_BROKER_PORT=str(self.broker.port), AGENT_VAULT_AGENT_ID="test")
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "vault_status"}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "vault_list"}}]
        process = subprocess.run([sys.executable, "-B", "-m", "agent_vault.mcp_server"],
            input="\n".join(json.dumps(m) for m in messages)+"\n", capture_output=True,
            text=True, env=env, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        replies = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertTrue(json.loads(replies[1]["result"]["content"][0]["text"])["connected"])
        pending = self.call("vault_begin_enrollment", {"service": "deepseek-api", "account": "main"})
        self.assertEqual(self.post("/api/submit", {"request_id": pending["request_id"], "secret": SECRET})[0], 200)
        self.assertEqual(self.call("vault_result", {"request_id": pending["request_id"]})["status"], "captured")
        self.assertEqual(self.remote.rows[0]["credential_type"], "api_key")
        self.assertEqual(self.post("/api/submit", {"request_id": pending["request_id"], "secret": SECRET})[0], 409)
        self.assertEqual(self.remote.writes, 1)
        self.assertEqual(len(self.call("vault_list")["connections"]), 1)
        self.assertEqual(self.call("execute_operation", {"request_id": "a"*32,"connection_id": str(uuid.uuid4()),
            "operation_id": "mock.account_summary", "expected_record_version": 1})["error"], "remote_execution_unsupported")
        self.assertFalse(Path(self.directory, "vault.sqlite").exists())
        for file in Path(self.root).rglob("*"):
            if file.is_file():
                if file.name == "core.lock":
                    # Windows denies reads of the actively locked byte. The
                    # singleton lease file contains only a fixed one-byte marker.
                    self.assertEqual(file.stat().st_size, 1)
                    continue
                self.assertNotIn(TOKEN.encode(), file.read_bytes())
                self.assertNotIn(SECRET.encode(), file.read_bytes())
        self.assertNotIn(TOKEN, process.stdout + process.stderr)

    def test_local_create_browser_unlock_shared_and_no_implicit_database(self):
        self.call("vault_select_target", {"mode": "local"})
        self.assertFalse(Path(self.directory).exists())
        self.assertEqual(self.post("/api/create", {"passphrase": PASSWORD, "confirm": "wrong"})[0], 400)
        self.assertEqual(self.post("/api/create", {"passphrase": PASSWORD, "confirm": PASSWORD})[0], 200)
        self.assertTrue(self.call("vault_status")["connected"])
        self.post("/api/logout", {})
        self.assertFalse(self.call("vault_status")["connected"])
        self.assertEqual(self.post("/api/login", {"passphrase": PASSWORD})[0], 200)
        self.assertTrue(self.call("vault_status")["connected"])
        pending = self.call("vault_begin_enrollment", {"service": "deepseek-api", "account": "main"})
        self.assertEqual(self.post("/api/submit", {"request_id": pending["request_id"], "secret": SECRET})[0], 200)
        self.assertEqual(self.call("vault_result", {"request_id": pending["request_id"]})["status"], "captured")

    def test_switch_failure_keeps_old_session_success_invalidates_requests(self):
        self.remote_login()
        pending = self.call("vault_begin_enrollment", {"service": "deepseek-api", "account": "main"})
        self.call("vault_select_target", {"mode": "remote", "server_url": self.remote.url})
        self.assertEqual(self.post("/api/login", {"username": "synthetic-user", "passphrase": "wrong"})[0], 401)
        self.assertTrue(self.call("vault_status")["connected"])
        self.assertEqual(self.call("vault_result", {"request_id": pending["request_id"]})["status"], "pending")
        self.post("/api/login", {"username": "synthetic-user", "passphrase": PASSWORD})
        self.assertEqual(self.call("vault_result", {"request_id": pending["request_id"]})["error"], "request_not_found")

    def test_uninitialized_remote_without_create_api_does_not_create(self):
        self.remote.mode = "uninitialized-no-create"
        result = self.call("vault_select_target", {"mode": "remote", "server_url": self.remote.url})
        self.assertEqual(result["phase"], "needs_create")
        self.assertFalse(result["creation_supported"])
        self.assertEqual(self.post("/api/create", {"username": "synthetic-user", "passphrase": PASSWORD, "confirm": PASSWORD})[1]["error"], "remote_creation_unsupported")
        self.assertEqual(self.remote.writes, 0)

    def test_uncertain_write_is_not_retried(self):
        self.remote_login()
        pending = self.call("vault_begin_enrollment", {"service": "deepseek-api", "account": "main"})
        self.remote.mode = "uncertain"
        data = {"request_id": pending["request_id"], "secret": SECRET}
        self.assertEqual(self.post("/api/submit", data)[1]["error"], "save_unconfirmed")
        self.assertEqual(self.call("vault_result", {"request_id": pending["request_id"]})["status"], "save_unconfirmed")
        self.assertEqual(self.post("/api/submit", data)[0], 409)
        self.assertEqual(self.remote.writes, 1)

    def test_security_guards_and_no_secret_fields(self):
        self.assertTrue(self.client.verify())
        self.assertIsNone(ensure_running(self.directory, self.broker.port))
        self.assertEqual(self.fetch("/api/select", {"mode": "local"}, {"X-Vault-CSRF": "bad"})[0], 403)
        self.assertEqual(self.fetch("/api/select", {"mode": "local"}, {"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.fetch("/rpc", {"action": "status", "payload": {}})[0], 403)
        self.assertEqual(self.fetch("/", extra={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.call("vault_status", {"password": SECRET})["error"], "invalid_tool_request")
        self.assertEqual(self.call("vault_select_target", {"mode": "remote", "server_url": "https://user:pass@host"})["error"], "invalid_server_url")

    def test_session_revocation_and_subject_isolation(self):
        self.remote_login()
        pending = self.call("vault_begin_enrollment", {"service": "deepseek-api", "account": "main"})
        other = McpServer(self.client, agent_id="other")
        result = other.call_tool("vault_result", {"request_id": pending["request_id"]})
        self.assertIn('forbidden', result["content"][0]["text"])
        self.remote.unauthorized = True
        self.assertEqual(self.call("vault_list")["error"], "session_expired")
        self.assertFalse(self.call("vault_status")["connected"])

    def test_bad_local_database_not_offered_as_new(self):
        Path(self.directory).mkdir()
        Path(self.directory, "vault.sqlite").write_bytes(b"broken sqlite")
        self.assertEqual(self.call("vault_select_target", {"mode": "local"})["error"], "local_backend_unavailable")
        self.assertEqual(Path(self.directory, "vault.sqlite").read_bytes(), b"broken sqlite")

    def test_second_core_for_same_scope_is_rejected_on_another_port(self):
        duplicate = Broker(self.directory, 0, allow_loopback_http=True)
        with self.assertRaisesRegex(VaultError, "core_already_running"):
            duplicate.build_server()

    def test_wrong_core_scope_and_legacy_port_refused(self):
        other_dir = self.root + "/different"
        other = CoreClient(other_dir, self.broker.port)
        self.assertFalse(other.verify())
        with self.assertRaisesRegex(VaultError, "broker_port_in_use"):
            ensure_running(other_dir, self.broker.port)

    def restart_core(self):
        port = self.broker.port
        self.server.shutdown()
        self.server.server_close()  # shutdown preserves protected device memory
        self.thread.join(3)
        self.broker = Broker(self.directory, port, allow_loopback_http=True)
        self.server = self.broker.build_server()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        _, body = self.fetch("/")
        self.csrf = re.search(r'name="vault-csrf" content="([^\"]+)"', body).group(1)

    def test_remembered_remote_survives_core_restart_and_has_no_one_hour_limit(self):
        from unittest.mock import patch
        import time
        self.remote_login()
        self.restart_core()
        state = self.call("vault_status")
        self.assertTrue(state["connected"])
        self.assertTrue(state["remember_device"])
        self.assertIsNone(state["session_remaining_s"])
        with patch("agent_vault.connection.time.monotonic", return_value=time.monotonic() + 86400):
            self.assertTrue(self.call("vault_status")["connected"])
        self.assertEqual(self.call("vault_list")["connections"], [])

    def test_remembered_local_unlock_survives_core_restart(self):
        self.call("vault_select_target", {"mode": "local"})
        self.post("/api/create", {"passphrase": PASSWORD, "confirm": PASSWORD})
        self.restart_core()
        self.assertTrue(self.call("vault_status")["connected"])
        self.assertEqual(self.call("vault_list")["connections"], [])

    def test_server_token_rotation_auto_reauthenticates_without_replaying_writes(self):
        self.remote_login()
        self.remote.token = "synthetic-rotated-server-signing-session"
        self.assertEqual(self.call("vault_list")["connections"], [])
        request = self.call("vault_begin_enrollment", {"service": "deepseek-api", "account": "main"})
        self.remote.token = "synthetic-second-server-update-session"
        self.assertEqual(self.post("/api/submit", {"request_id": request["request_id"], "secret": SECRET})[0], 200)
        self.assertEqual(self.remote.writes, 1)
        self.assertTrue(self.call("vault_status")["connected"])

    def test_password_change_requires_login_and_forgets_rejected_device(self):
        self.remote_login()
        self.remote.password = "synthetic-new-password"
        self.remote.token = "synthetic-token-after-password-change"
        self.assertEqual(self.call("vault_list")["error"], "session_expired")
        self.assertFalse(self.call("vault_status")["connected"])
        self.assertNotIn("device", json.loads(Path(self.directory + ".connector", "target.json").read_text()))
        self.restart_core()
        self.assertEqual(self.call("vault_status")["phase"], "needs_login")

    def test_temporary_server_outage_preserves_memory_and_recovers(self):
        from unittest.mock import patch
        import time
        self.remote_login()
        self.remote.unavailable = True
        self.restart_core()
        state = self.call("vault_status")
        self.assertFalse(state["connected"])
        self.assertTrue(state["remember_device"])
        self.assertIn("device", json.loads(Path(self.directory + ".connector", "target.json").read_text()))
        self.remote.unavailable = False
        with patch("agent_vault.connection.time.monotonic", return_value=time.monotonic() + 60):
            self.assertTrue(self.call("vault_status")["connected"])

    def test_logout_forgets_device_and_opt_out_does_not_restore(self):
        self.remote_login()
        self.post("/api/logout", {})
        self.restart_core()
        self.assertEqual(self.call("vault_status")["phase"], "needs_login")
        self.post("/api/login", {"username": "synthetic-user", "passphrase": PASSWORD, "remember_device": False})
        self.restart_core()
        self.assertFalse(self.call("vault_status")["connected"])

    def test_local_credential_scope_and_controlled_use(self):
        self.call("vault_select_target", {"mode": "local"})
        self.post("/api/create", {"passphrase": PASSWORD, "confirm": PASSWORD})
        request = self.call("vault_begin_enrollment", {"service": "magpie", "account": "dsh",
                                                       "credential_type": "api_key",
                                                       "allowed_operations": ["chat"]})
        self.post("/api/submit", {"request_id": request["request_id"], "secret": SECRET})
        listing = self.call("vault_list")
        stored = [row for row in listing["connections"] if row["service_id"] == "magpie"]
        self.assertEqual(len(stored), 1)
        scope = self.client.command("consume", {"connection_id": stored[0]["connection_id"],
                                                 "scope_only": True})
        self.assertEqual(scope["allowed_operations"], ["chat"])
        used = self.client.command("consume", {"connection_id": stored[0]["connection_id"],
                                               "operation": "chat"})
        self.assertEqual(used["secret"], SECRET)
        with self.assertRaises(VaultError):
            self.client.command("consume", {"connection_id": stored[0]["connection_id"],
                                            "operation": "embed"})
        # The plaintext must never be reachable through the MCP tool surface.
        tool_result = self.call("vault_list")
        self.assertNotIn(SECRET, json.dumps(tool_result))

    def test_remote_enrollment_preserves_operations_and_exposes_scope(self):
        self.remote_login()
        pending = self.call("vault_begin_enrollment", {"service": "magpie", "account": "review",
                                                       "credential_type": "api_key",
                                                       "allowed_operations": ["chat"]})
        self.post("/api/submit", {"request_id": pending["request_id"], "secret": SECRET})
        # The requested scope must reach the server verbatim.
        self.assertEqual(self.remote.rows[-1]["allowed_operations"], ["chat"])
        # Scope is visible through metadata ("everything except the secret").
        matches = self.call("vault_find", {"service_id": "magpie"})["matches"]
        review = [row for row in matches if row["account_alias"] == "review"][0]
        self.assertEqual(review["allowed_operations"], ["chat"])
        # And consume with the granted operation now works for the new key.
        consumed = self.client.command("consume", {"connection_id": review["connection_id"],
                                                   "operation": "chat"})
        self.assertEqual(consumed["secret"], SECRET)

    def test_denied_operation_keeps_remote_session(self):
        self.remote_login()
        self.remote.forbidden = True
        denied = self.call("vault_list", {})
        self.assertIn("error", denied)
        self.assertTrue(self.call("vault_status")["connected"],
                        "a 403 must not clear the remembered session")

    def test_export_writes_file_without_leaking_secret(self):
        self.call("vault_select_target", {"mode": "local"})
        self.post("/api/create", {"passphrase": PASSWORD, "confirm": PASSWORD})
        request = self.call("vault_begin_enrollment", {"service": "magpie", "account": "dsh",
                                                       "credential_type": "api_key",
                                                       "allowed_operations": ["chat"]})
        self.post("/api/submit", {"request_id": request["request_id"], "secret": SECRET})
        stored = [row for row in self.call("vault_list")["connections"]
                  if row["service_id"] == "magpie"][0]
        exported = self.call("vault_export_credential", {
            "connection_id": stored["connection_id"], "operation": "chat",
            "filename": "magpie-dsh.key"})
        self.assertNotIn(SECRET, json.dumps(exported))
        path = Path(exported["path"])
        self.assertTrue(path.is_file())
        self.assertEqual(path.read_text(), SECRET)
        self.assertEqual(path.parent.name, "exports")
        # Atomic overwrite: a second export to the same name replaces content.
        again = self.call("vault_export_credential", {
            "connection_id": stored["connection_id"], "operation": "chat",
            "filename": "magpie-dsh.key"})
        self.assertEqual(Path(again["path"]).read_text(encoding="utf-8"), SECRET)
        # Operations outside the credential scope stay denied and leave no file.
        denied = self.call("vault_export_credential", {
            "connection_id": stored["connection_id"], "operation": "embed",
            "filename": "other.key"})
        self.assertEqual(denied["error"], "operation_denied")
        self.assertFalse(Path(self.directory + ".connector", "exports", "other.key").exists())
        # Destination must be an absolute local path; UNC and relative refused.
        for bad_destination in ("\\\\server\\share", "relative/dir", ".."):
            body = self.call("vault_export_credential", {
                "connection_id": stored["connection_id"], "operation": "chat",
                "filename": "moved.key", "destination": bad_destination})
            self.assertEqual(body["error"], "invalid_destination")
        custom = os.path.join(self.root, "custom-destination")
        moved = self.call("vault_export_credential", {
            "connection_id": stored["connection_id"], "operation": "chat",
            "filename": "moved.key", "destination": custom})
        self.assertEqual(Path(moved["path"]).read_text(encoding="utf-8"), SECRET)
        self.assertFalse(Path(self.directory + ".connector", "exports", "moved.key").exists())
        # Traversal and hidden names are refused.
        for bad in ("../escape.key", "sub/dir.key", ".hidden"):
            body = self.call("vault_export_credential", {
                "connection_id": stored["connection_id"], "operation": "chat", "filename": bad})
            self.assertEqual(body["error"], "invalid_filename")

    def test_export_json_format_for_login_credentials(self):
        self.call("vault_select_target", {"mode": "local"})
        self.post("/api/create", {"passphrase": PASSWORD, "confirm": PASSWORD})
        request = self.call("vault_begin_enrollment", {"service": "some-agent", "account": "bot-login",
                                                       "credential_type": "password",
                                                       "allowed_operations": ["read"]})
        self.post("/api/submit", {"request_id": request["request_id"], "secret": SECRET})
        stored = [row for row in self.call("vault_list")["connections"]
                  if row["service_id"] == "some-agent"][0]
        exported = self.call("vault_export_credential", {
            "connection_id": stored["connection_id"], "operation": "read",
            "filename": "bot-login.json", "format": "json"})
        self.assertNotIn(SECRET, json.dumps(exported))
        envelope = json.loads(Path(exported["path"]).read_text(encoding="utf-8"))
        self.assertEqual(envelope, {"service": "some-agent", "account": "bot-login",
                                    "secret": SECRET})
        raw = self.call("vault_export_credential", {
            "connection_id": stored["connection_id"], "operation": "read",
            "filename": "bot-login.txt"})
        self.assertEqual(Path(raw["path"]).read_text(encoding="utf-8"), SECRET)
        bad = self.call("vault_export_credential", {
            "connection_id": stored["connection_id"], "operation": "read",
            "filename": "x.yaml", "format": "yaml"})
        self.assertEqual(bad["error"], "invalid_tool_request")

    def test_export_requires_authentication(self):
        body = self.call("vault_export_credential", {
            "connection_id": "0" * 36, "operation": "chat", "filename": "x.key"})
        self.assertIn(body["error"], ("login_required", "session_expired"))

    def test_unknown_operation_is_refused(self):
        body = self.call("vault_begin_enrollment", {"service": "magpie", "account": "x",
                                                    "allowed_operations": ["delete-everything"]})
        self.assertEqual(body["error"], "invalid_tool_request")

    def test_config_write_failure_does_not_switch_active_session(self):
        from unittest.mock import patch
        self.remote_login()
        before = self.call("vault_status")["generation"]
        self.call("vault_select_target", {"mode": "remote", "server_url": self.remote.url})
        with patch("agent_vault.connection.os.replace", side_effect=OSError("synthetic filesystem failure")):
            code, result = self.post("/api/login", {"username": "synthetic-user", "passphrase": PASSWORD})
        self.assertEqual((code, result["error"]), (503, "target_config_unavailable"))
        self.assertEqual(self.call("vault_status")["generation"], before)
        self.assertTrue(self.call("vault_status")["connected"])

    def test_saved_local_target_overrides_old_installation_default(self):
        from agent_vault.connection import ConnectionCore
        self.call("vault_select_target", {"mode": "local"})
        self.post("/api/create", {"passphrase": PASSWORD, "confirm": PASSWORD})
        self.post("/api/logout", {})
        recovered = ConnectionCore(self.directory, server_url="https://unused.invalid")
        self.assertEqual(recovered.status()["candidate_mode"], "local")
        self.assertEqual(recovered.status()["phase"], "needs_unlock")

    def test_opt_out_session_ttl_requires_login_again(self):
        from unittest.mock import patch
        import time
        self.remote_login(remember=False)
        with patch("agent_vault.connection.time.monotonic", return_value=time.monotonic() + 7200):
            state = self.call("vault_status")
        self.assertFalse(state["connected"])
        self.assertEqual(state["phase"], "needs_login")

    def test_stale_login_form_does_not_authenticate_new_target(self):
        first = self.call("vault_select_target", {"mode": "remote", "server_url": self.remote.url})
        self.call("vault_select_target", {"mode": "remote", "server_url": self.remote.url})
        code, result = self.post("/api/login", {"username": "synthetic-user", "passphrase": PASSWORD,
                                                "selection_id": first["selection_id"]})
        self.assertEqual((code, result["error"]), (409, "target_selection_changed"))
        self.assertFalse(self.call("vault_status")["connected"])

    def test_startup_uses_authenticated_probe(self):
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        directory = self.root + "/spawn"
        child = ensure_running(directory, port)
        try:
            self.assertIsNotNone(child)
            self.assertTrue(CoreClient(directory, port).verify())
        finally:
            if child:
                child.terminate()
                child.wait(5)


if __name__ == "__main__":
    unittest.main()
