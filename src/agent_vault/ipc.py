"""Authenticated loopback transport; no database or login state in MCP clients."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import urllib.error
import urllib.parse
import urllib.request

from .errors import VaultError
from .guard import platform_guard

PROTOCOL = "agent-vault-connector/2"


def control_key(directory: str) -> str:
    guard = platform_guard()
    folder = guard.ensure_private_directory(os.path.abspath(directory) + ".connector", create=True)
    path = os.path.join(folder, "broker.key")
    if not os.path.exists(path):
        try:
            guard.create_private_file(path, secrets.token_hex(32).encode("ascii"))
        except FileExistsError:
            pass
    guard.check_file(path)
    value = Path(path).read_text(encoding="ascii")
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise VaultError(500, "broker_key_invalid")
    return value


def scope_id(directory: str) -> str:
    return hashlib.sha256(os.path.normcase(os.path.abspath(directory)).encode()).hexdigest()


class CoreLease:
    """OS-owned lock prevents two core processes for one configuration scope,
    including accidental launches on different ports. Released on process exit.
    """
    def __init__(self, directory: str):
        folder = os.path.abspath(directory) + ".connector"
        self.stream = open(os.path.join(folder, "core.lock"), "a+b")
        try:
            if self.stream.seek(0, 2) == 0:
                self.stream.write(b"1")
                self.stream.flush()
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise VaultError(409, "core_already_running") from None

    def close(self):
        if self.stream.closed:
            return
        try:
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.stream.close()


class CoreClient:
    def __init__(self, directory: str, port: int = 43122):
        self.directory = directory
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.key = control_key(directory)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def verify(self) -> bool:
        challenge = secrets.token_hex(16)
        try:
            with self.opener.open(self.url + "/health?challenge=" + challenge, timeout=1) as response:
                data = json.loads(response.read(4096))
            expected = hmac.new(self.key.encode(), (PROTOCOL + challenge + scope_id(self.directory)).encode(),
                                hashlib.sha256).hexdigest()
            return (isinstance(data, dict) and data.get("protocol") == PROTOCOL and data.get("scope") == scope_id(self.directory)
                    and hmac.compare_digest(str(data.get("proof", "")), expected))
        except (OSError, ValueError):
            return False

    def call_tool(self, name: str, arguments: dict, auth: dict) -> dict:
        return self.command("tool", {"name": name, "arguments": arguments, "auth": auth})

    def command(self, action: str, payload: dict, _recovered: bool = False) -> dict:
        # Self-healing: if the core died since the last use, transparently
        # bring it back once and retry. Remembered devices make the new
        # process reconnect automatically; pending requests do not survive.
        # Only connection-level failures trigger recovery — HTTP error
        # statuses from the core are real answers and must pass through.
        if not self.verify():
            if not _recovered:
                from .broker import ensure_running
                ensure_running(self.directory, self.port)
                return self.command(action, payload, _recovered=True)
            raise VaultError(503, "core_unavailable_or_mismatched")
        request = urllib.request.Request(self.url + "/rpc", method="POST",
            data=json.dumps({"action": action, "payload": payload}).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.key})
        try:
            try:
                response = self.opener.open(request, timeout=20)
            except urllib.error.HTTPError as error:
                response = error  # error statuses still carry our JSON envelope
            with response:
                body = response.read(1024 * 1024 + 1)
                if len(body) > 1024 * 1024:
                    raise VaultError(502, "core_response_invalid")
                data = json.loads(body)
                if not isinstance(data, dict):
                    raise VaultError(502, "core_response_invalid")
                if response.code != 200:
                    code = data.get("error", "core_unavailable")
                    raise VaultError(response.code, code if isinstance(code, str) else "core_unavailable")
                return data
        except VaultError:
            raise
        except ValueError:
            raise VaultError(502, "core_response_invalid") from None
        except OSError:
            # Once POST has been attempted its outcome is unknown. Replaying
            # can duplicate enrollment, writes or credential use. Recovery is
            # safe only above, before dispatch; the next command may restart.
            raise VaultError(503, "core_response_unconfirmed") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
