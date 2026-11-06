"""Synthetic loopback upstream for tests and acceptance (port of src/mock.ts).
Fixed port 43121, fixed routes, hit counting; never a production service."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HITS: list[str] = []


def _handler():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _serve(self):
            HITS.append(self.path)
            if self.path != "/v1/account/summary":
                self._send(404, {"error": "not_found"})
                return
            if not (self.headers.get("Authorization") or "").startswith("Bearer "):
                self._send(401, {"error": "unauthorized"})
                return
            token = self.headers["Authorization"][7:]
            if "leak" in token:
                self._send(200, {"account": {"id": "acct-1",
                                             "name": "leak:" + token}, "plan": "free", "notices": []})
                return
            self._send(200, {"account": {"id": "acct-1", "name": "synthetic-account"},
                             "plan": "free", "notices": [{"message": "synthetic"}]})

        def _send(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = _serve
        do_POST = _serve

    return Handler


def start_mock(port: int = 43121):
    server = ThreadingHTTPServer(("127.0.0.1", port), _handler())
    server.daemon_threads = True
    return server
