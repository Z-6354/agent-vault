"""Single local connection owner. Browser and authenticated MCP clients use
this same service; MCP processes never construct their own Vault instances.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .connection import ConnectionCore, ADMIN
from .errors import VaultError
from .guard import GuardError
from .ipc import CoreClient, CoreLease, PROTOCOL, control_key, scope_id
from .remote import Remote

DEFAULT_PORT = 43122
MAX_BODY = 512 * 1024
WEB = Path(__file__).with_name("web")
_CHILDREN = []


def port_open(port: int, timeout: float = 0.3) -> bool:
    with socket.socket() as sock:
        sock.settimeout(timeout)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def ensure_running(directory: str, port: int = DEFAULT_PORT,
                   python_executable: str | None = None) -> subprocess.Popen | None:
    client = CoreClient(directory, port)
    if client.verify():
        return None
    if port_open(port):
        raise VaultError(409, "broker_port_in_use_or_old_version")
    root = str(Path(__file__).resolve().parent.parent)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (root, env.get("PYTHONPATH"))))
    options = ({"creationflags": 0x00000008 | 0x00000200} if os.name == "nt"
               else {"start_new_session": True})
    diagnostic = env.get("AGENT_VAULT_TEST_DIAGNOSTICS") == "1"
    log = None
    if diagnostic:
        log = open(os.path.join(os.path.abspath(directory) + ".connector", "startup-test.log"), "ab")
    try:
        child = subprocess.Popen([python_executable or sys.executable, "-B", "-m", "agent_vault",
            "serve", "--data-dir", directory, "--port", str(port)], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=log if log else subprocess.DEVNULL,
            env=env, cwd=root, **options)
    finally:
        if log:
            log.close()
    _CHILDREN.append(child)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if client.verify():
            return child
        if child.poll() is not None:
            # Another concurrently starting MCP may have won the bind race.
            if client.verify():
                return None
            raise VaultError(503, "core_start_failed")
        time.sleep(.1)
    if diagnostic:
        log_path = Path(os.path.abspath(directory) + ".connector") / "startup-test.log"
        print("Synthetic startup diagnostics: port_open=" + str(port_open(port)), file=sys.stderr)
        if log_path.exists():
            print(log_path.read_text(errors="replace")[-8000:], file=sys.stderr)
    child.terminate()
    child.wait(timeout=5)
    raise VaultError(503, "core_start_timeout")


class Broker:
    def __init__(self, directory: str, port: int = DEFAULT_PORT, *, server_url=None,
                 allow_loopback_http=False):
        self.directory = os.path.abspath(directory)
        self.port = port
        self.key = control_key(directory)
        self.browser_session = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.core = ConnectionCore(directory,
            server_url=server_url or os.environ.get("AGENT_VAULT_SERVER_URL"),
            allow_loopback_http=allow_loopback_http)

    def state(self) -> dict:
        with self.core.lock:
            return self.core.status() | {"pending": self.core.pending()}

    def build_server(self) -> ThreadingHTTPServer:
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def setup(self):
                super().setup()
                self.connection.settimeout(10)

            def valid_host(self):
                return self.headers.get("Host") in (f"127.0.0.1:{broker.port}", f"localhost:{broker.port}")

            def browser_authorized(self):
                from http.cookies import SimpleCookie
                cookie = SimpleCookie()
                try:
                    cookie.load(self.headers.get("Cookie", ""))
                    value = cookie.get("vault_browser")
                    return bool(value and hmac.compare_digest(value.value, broker.browser_session))
                except Exception:
                    return False

            def valid_browser_post(self):
                origin = self.headers.get("Origin")
                allowed = (f"http://127.0.0.1:{broker.port}", f"http://localhost:{broker.port}")
                # Origin absent is permitted for a trusted terminal client only
                # when it presents the same authenticated browser credentials.
                return (self.browser_authorized() and (origin is None or origin in allowed)
                    and hmac.compare_digest(self.headers.get("X-Vault-CSRF", ""), broker.csrf))

            def send(self, status, body, content_type="application/json; charset=utf-8", *, cookie=False):
                payload = json.dumps(body, ensure_ascii=False).encode() if isinstance(body, dict) else body
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; "
                    "style-src 'self'; connect-src 'self'; img-src 'self' data:; "
                    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
                if cookie:
                    self.send_header("Set-Cookie", f"vault_browser={broker.browser_session}; Path=/; HttpOnly; SameSite=Strict")
                self.end_headers()
                self.wfile.write(payload)

            def read_json(self):
                try:
                    if self.headers.get("Transfer-Encoding"):
                        raise ValueError()
                    length = int(self.headers.get("Content-Length", "-1"))
                    if not 0 < length <= MAX_BODY or self.headers.get_content_type() != "application/json":
                        raise ValueError()
                    value = json.loads(self.rfile.read(length))
                    if not isinstance(value, dict):
                        raise ValueError()
                    return value
                except (ValueError, UnicodeError):
                    raise VaultError(400, "invalid_json") from None

            def do_GET(self):
                if not self.valid_host():
                    self.send(403, {"error": "invalid_host"})
                    return
                path = urlsplit(self.path).path
                if path == "/health":
                    challenge = parse_qs(urlsplit(self.path).query).get("challenge", [""])[0]
                    if len(challenge) != 32 or any(c not in "0123456789abcdef" for c in challenge):
                        self.send(400, {"error": "invalid_challenge"})
                        return
                    proof = hmac.new(broker.key.encode(), (PROTOCOL + challenge + scope_id(broker.directory)).encode(),
                                     hashlib.sha256).hexdigest()
                    self.send(200, {"protocol": PROTOCOL, "scope": scope_id(broker.directory), "proof": proof})
                elif path in ("/", "/init", "/login") or path.startswith("/connect/"):
                    page = (WEB / "index.html").read_text(encoding="utf-8").replace("__CSRF__", broker.csrf)
                    self.send(200, page.encode(), "text/html; charset=utf-8", cookie=True)
                elif path in ("/assets/style.css", "/assets/app.js"):
                    name = "style.css" if path.endswith(".css") else "app.js"
                    mime = "text/css" if name.endswith(".css") else "text/javascript"
                    self.send(200, (WEB / name).read_bytes(), mime + "; charset=utf-8")
                elif path == "/api/status" and self.browser_authorized():
                    self.send(200, broker.state())
                else:
                    self.send(404, {"error": "not_found"})

            def do_POST(self):
                if not self.valid_host():
                    self.send(403, {"error": "invalid_host"})
                    return
                path = urlsplit(self.path).path
                internal = path == "/rpc"
                if internal:
                    expected = "Bearer " + broker.key
                    if not hmac.compare_digest(self.headers.get("Authorization", ""), expected):
                        self.send(403, {"error": "forbidden"})
                        return
                    if self.headers.get("Origin"):
                        self.send(403, {"error": "forbidden"})
                        return
                elif not self.valid_browser_post():
                    self.send(403, {"error": "forbidden"})
                    return
                try:
                    data = self.read_json()
                    if internal:
                        result = broker.rpc(data)
                    else:
                        result = broker.browser_action(path, data)
                    self.send(200, result)
                except VaultError as error:
                    self.send(error.status, {"error": error.code})
                except (GuardError, OSError, ValueError):
                    self.send(503, {"error": "backend_unavailable"})

        lease = CoreLease(self.directory)
        class CoreServer(ThreadingHTTPServer):
            daemon_threads = True
            def server_close(self):
                try:
                    super().server_close()
                    broker.core.close()
                finally:
                    lease.close()
        try:
            server = CoreServer(("127.0.0.1", self.port), Handler)
        except BaseException:
            lease.close()
            raise
        self.port = server.server_address[1]
        return server

    def browser_action(self, path, data):
        with self.core.lock:
            if path == "/api/select":
                return self.core.select(data.get("mode"), data.get("server_url"))
            if path in ("/api/login", "/api/create"):
                return self.core.authenticate(path.rsplit("/", 1)[-1], data)
            if path == "/api/logout":
                return self.core.logout()
            if path == "/api/cancel-selection":
                return self.core.cancel_selection()
            if path == "/api/submit":
                return self.core.complete(data.get("request_id"), data.get("secret"))
            if path == "/api/decline":
                return self.core.decline(data.get("request_id"))
            raise VaultError(404, "not_found")

    def rpc(self, data):
        action, payload = data.get("action"), data.get("payload")
        if not isinstance(payload, dict):
            raise VaultError(400, "invalid_request")
        with self.core.lock:
            if action == "tool":
                # Validation is shared with stdio, not trusted merely because
                # the caller passed the loopback control authentication.
                from .mcp_server import validate_arguments
                name, args = payload.get("name"), payload.get("arguments")
                validate_arguments(name, args)
                return self.core.call_tool(name, args, payload.get("auth"))
            if action == "status":
                return self.core.status()
            if action in ("login", "create"):
                return self.core.authenticate(action, payload)
            if action == "complete":
                return self.core.complete(payload.get("request_id"), payload.get("secret"))
            if action == "logout":
                return self.core.logout()
            if action == "consume":
                # Internal executors only: the control key is required and the
                # plaintext is returned to this process, never to MCP.
                backend = self.core._ready()
                if isinstance(backend, Remote):
                    if payload.get("scope_only"):
                        return self.core.credential_scope(payload.get("connection_id"))
                    return backend.consume(payload.get("connection_id"),
                                           payload.get("operation", "read"),
                                           payload.get("caller", "agent"))
                if payload.get("scope_only"):
                    return self.core.credential_scope(payload.get("connection_id"))
                return self.core.consume_local(payload.get("connection_id"),
                                               payload.get("operation", "read"),
                                               payload.get("caller", "agent"))
            if action == "manage":
                backend = self.core._ready()
                if isinstance(backend, Remote):
                    raise VaultError(403, "remote_management_unsupported")
                method = payload.get("method")
                if method == "grant":
                    return backend.grant_agent(ADMIN, payload.get("agent_id"), payload.get("operations"))
                if method == "revoke":
                    return backend.revoke_agent(ADMIN, payload.get("agent_id"), payload.get("operations"))
                if method == "agents":
                    return {"agents": backend.list_agents(ADMIN)}
            raise VaultError(400, "invalid_request")

    def serve_forever(self):
        server = self.build_server()
        try:
            server.serve_forever(poll_interval=.2)
        except KeyboardInterrupt:
            pass
        finally:
            self.core.close()
            server.server_close()
