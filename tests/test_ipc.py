"""A lost response must not duplicate an accepted state-changing command."""
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

from agent_vault.errors import VaultError
from agent_vault.ipc import CoreClient, PROTOCOL, scope_id
from helpers import cleanup, test_directory


class IPCOutcomeTests(unittest.TestCase):
    def test_lost_post_response_is_not_replayed(self):
        root = test_directory("lost-response-")
        self.addCleanup(cleanup, root)
        client = CoreClient(root + "/data", 0)
        writes = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                challenge = parse_qs(urlsplit(self.path).query)["challenge"][0]
                proof = hmac.new(client.key.encode(),
                    (PROTOCOL + challenge + scope_id(client.directory)).encode(), hashlib.sha256).hexdigest()
                raw = json.dumps({"protocol": PROTOCOL, "scope": scope_id(client.directory), "proof": proof}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def do_POST(self):
                writes.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                # The side effect was accepted, but no response was delivered.
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client.port = server.server_port
            client.url = f"http://127.0.0.1:{server.server_port}"
            with self.assertRaisesRegex(VaultError, "core_response_unconfirmed"):
                client.command("synthetic_mutation", {"request_id": "test"})
            self.assertEqual(len(writes), 1, "accepted mutation must not be sent a second time")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)
