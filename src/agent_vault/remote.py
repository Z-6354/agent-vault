"""Bounded HTTPS adapter for the existing Agent Vault Service v1 contract.
Never expose response bodies, tokens or raw consume to callers of MCP.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from .errors import VaultError
from . import registry

MAX_RESPONSE = 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_url(value: object, *, allow_loopback_http: bool = False) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) <= 32 for c in value):
        raise VaultError(400, "invalid_server_url")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise VaultError(400, "invalid_server_url") from None
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.scheme not in ("http", "https")
            or (port is not None and not 1 <= port <= 65535)):
        raise VaultError(400, "invalid_server_url")
    if parsed.scheme != "https" and not (allow_loopback_http and parsed.hostname == "127.0.0.1"):
        raise VaultError(400, "https_required")
    if any(part in (".", "..") for part in parsed.path.split("/")):
        raise VaultError(400, "invalid_server_url")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path.rstrip("/"), "", ""))


class Remote:
    def __init__(self, url: str, *, allow_loopback_http: bool = False):
        self.url = normalize_url(url, allow_loopback_http=allow_loopback_http)
        self.token: str | None = None
        self.deadline = 0.0
        self.username = ""
        self.setup_path: str | None = None
        self.initialization = "unknown"
        self.renew = None  # supplied only by the single owner for remembered devices
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    @property
    def authenticated(self) -> bool:
        # Server acceptance decides token validity; the core separately applies
        # its one-hour limit only when the user opted out of remembering.
        return bool(self.token)

    def clear(self) -> None:
        self.token = None
        self.deadline = 0
        self.username = ""

    def request(self, method: str, path: str, data=None, *, auth=False, recover=True) -> tuple[int, object]:
        headers = {"Accept": "application/json"}
        if auth:
            if not self.authenticated:
                raise VaultError(401, "session_expired")
            headers["Authorization"] = "Bearer " + self.token
        raw = None
        if data is not None:
            raw = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url + path, data=raw, headers=headers, method=method)
        try:
            try:
                response = self.opener.open(req, timeout=8)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                status = response.code
                if auth and status in (401, 403):
                    if status == 403:
                        # Authorization refusal: this operation is denied, but
                        # the session token itself stays valid.
                        raise VaultError(403, "operation_denied")
                    self.clear()
                    if recover and self.renew is not None:
                        self.renew()
                        if method == "GET":
                            return self.request(method, path, data, auth=auth, recover=False)
                        # Never replay a mutating request after uncertain I/O.
                        raise VaultError(409, "save_unconfirmed")
                    raise VaultError(status, "session_expired")
                if status >= 400:
                    # Do not read arbitrary error bodies: validation errors can echo inputs.
                    return status, {}
                body = response.read(MAX_RESPONSE + 1)
                if len(body) > MAX_RESPONSE:
                    raise VaultError(502, "remote_response_invalid")
                return status, json.loads(body)
        except urllib.error.URLError as error:
            reason = error.reason
            if isinstance(reason, ssl.SSLError):
                code = "tls_failed"
            elif isinstance(reason, socket.gaierror):
                code = "dns_failed"
            elif isinstance(reason, (TimeoutError, socket.timeout)):
                code = "connection_timeout"
            elif isinstance(reason, ConnectionRefusedError):
                code = "connection_refused"
            else:
                code = "network_unavailable"
            raise VaultError(503, code) from None
        except (TimeoutError, socket.timeout):
            raise VaultError(503, "connection_timeout") from None
        except (ValueError, UnicodeError):
            raise VaultError(502, "remote_response_invalid") from None

    def probe(self) -> dict:
        status, spec = self.request("GET", "/openapi.json")
        paths = spec.get("paths") if isinstance(spec, dict) else None
        required = {"/api/v1/auth/login", "/api/v1/auth/status", "/api/v1/credentials"}
        if status != 200 or not isinstance(paths, dict) or not required.issubset(paths):
            raise VaultError(502, "vault_service_not_verified")
        # Only use a setup contract actually advertised by the service.
        if "/api/v1/setup/status" in paths:
            status, info = self.request("GET", "/api/v1/setup/status")
            if status == 200 and isinstance(info, dict) and type(info.get("initialized")) is bool:
                self.initialization = "ready" if info["initialized"] else "uninitialized"
                if not info["initialized"] and "/api/v1/setup" in paths:
                    schema = spec.get("components", {}).get("schemas", {})
                    setup = paths["/api/v1/setup"].get("post", {}).get("requestBody", {})
                    shape = setup.get("content", {}).get("application/json", {}).get("schema", {})
                    if "$ref" in shape:
                        shape = schema.get(shape["$ref"].rsplit("/", 1)[-1], {})
                    # This adapter supports only a deliberately explicit setup body.
                    if (set(shape.get("required", [])) == {"username", "password"}
                            and set(shape.get("properties", {})) == {"username", "password"}):
                        self.setup_path = "/api/v1/setup"
            elif status not in (401, 403):
                raise VaultError(502, "remote_response_invalid")
        return {"reachable": True, "service_verified": True, "initialization": self.initialization,
                "creation_supported": bool(self.setup_path)}

    def login(self, username: object, password: object) -> None:
        if not isinstance(username, str) or not 1 <= len(username) <= 100:
            raise VaultError(400, "invalid_username")
        if not isinstance(password, str) or not 1 <= len(password) <= 1024:
            raise VaultError(400, "invalid_password")
        status, value = self.request("POST", "/api/v1/auth/login",
                                     {"username": username, "password": password})
        if status in (401, 403):
            raise VaultError(401, "login_rejected")
        if status >= 500 or status == 429:
            raise VaultError(503, "remote_auth_unavailable")
        token = value.get("token") if isinstance(value, dict) else None
        if status != 200 or not isinstance(token, str) or not 16 <= len(token) <= 8192:
            raise VaultError(502, "login_unconfirmed")
        if any(ord(c) <= 32 or ord(c) >= 127 for c in token):
            raise VaultError(502, "login_unconfirmed")
        self.token, self.username = token, username
        self.deadline = float("inf")
        try:
            status, _ = self.request("GET", "/api/v1/auth/status", auth=True, recover=False)
            if status != 200:
                raise VaultError(502, "login_unconfirmed")
        except BaseException:
            self.clear()
            raise

    def create(self, username, password, confirm) -> None:
        if self.initialization != "uninitialized" or not self.setup_path:
            raise VaultError(409, "remote_creation_unsupported")
        if not isinstance(password, str) or len(password) < 12 or password != confirm:
            raise VaultError(400, "passphrase_mismatch")
        status, _ = self.request("POST", self.setup_path, {"username": username, "password": password})
        if status not in (200, 201):
            raise VaultError(502, "creation_unconfirmed")
        self.login(username, password)

    def inventory(self) -> list[dict]:
        status, rows = self.request("GET", "/api/v1/credentials/list", auth=True)
        if status != 200 or not isinstance(rows, list):
            raise VaultError(502, "inventory_unavailable")
        safe = []
        for row in rows:
            if not isinstance(row, dict):
                raise VaultError(502, "remote_response_invalid")
            entry = {}
            for key in ("connection_id", "service_id", "account_alias", "credential_type"):
                if not isinstance(row.get(key), str) or len(row[key]) > 2048:
                    raise VaultError(502, "remote_response_invalid")
                entry[key] = row[key]
            # Operations are metadata the model must see ("everything except
            # the secret"); servers without the field project an empty scope.
            allowed = row.get("allowed_operations")
            entry["allowed_operations"] = [
                op for op in (allowed if isinstance(allowed, list) else [])
                if isinstance(op, str) and 1 <= len(op) <= 64]
            safe.append(entry)
        return safe

    def credential_metadata(self, connection_id: str) -> dict:
        """Metadata for one credential, including its allowed operations."""
        status, result = self.request("POST", "/api/v1/credentials/resolve",
                                      {"mode": "exact", "connection_id": connection_id}, auth=True)
        candidate = None
        if status == 200 and isinstance(result, dict):
            candidate = result.get("candidate") or result.get("resolved")
        if not isinstance(candidate, dict):
            raise VaultError(404, "connection_not_found")
        allowed = candidate.get("allowed_operations")
        if not isinstance(allowed, list) or any(not isinstance(op, str) for op in allowed):
            raise VaultError(502, "remote_response_invalid")
        return {"connection_id": str(candidate.get("connection_id") or connection_id),
                "service_id": str(candidate.get("service_id") or ""),
                "account_alias": str(candidate.get("account_alias") or ""),
                "credential_type": str(candidate.get("credential_type") or ""),
                "allowed_operations": allowed}

    def consume(self, connection_id: str, operation: str, caller: str = "agent") -> dict:
        """Audited retrieval of the plain secret for authorized execution only.

        The plaintext never crosses an MCP tool boundary; callers are the
        controlled executors inside this process.
        """
        if not isinstance(operation, str) or not 1 <= len(operation) <= 64:
            raise VaultError(400, "invalid_operation")
        status, result = self.request("POST", "/api/v1/credentials/consume",
                                      {"connection_id": connection_id, "operation": operation,
                                       "caller": caller}, auth=True)
        if status != 200 or not isinstance(result, dict) or result.get("status") != "granted":
            raise VaultError(403, "operation_denied")
        secret = result.get("secret")
        if not isinstance(secret, str) or not 1 <= len(secret) <= 65536:
            raise VaultError(502, "consume_unconfirmed")
        returned = result.get("connection_id")
        if returned is not None and str(returned) != str(connection_id):
            raise VaultError(502, "consume_unconfirmed")
        return {"secret": secret, "service_id": str(result.get("service_id") or ""),
                "account_alias": str(result.get("account_alias") or "")}

    def save(self, metadata: dict, secret: str,
             allowed_operations: list[str] | None = None) -> dict:
        # Renew an expired/rotated token with a read-only preflight before
        # dispatching the secret-bearing write. The write itself is never retried.
        status, _ = self.request("GET", "/api/v1/auth/status", auth=True)
        if status != 200:
            raise VaultError(503, "remote_auth_unavailable")
        status, result = self.request("POST", "/api/v1/credentials", {
            "service_id": metadata["service"], "account_alias": metadata["account"],
            "secret": secret, "credential_type": metadata["credential_type"],
            "allowed_operations": registry.validate_allowed_operations(allowed_operations),
        }, auth=True)
        if status != 200 or not isinstance(result, dict) or result.get("status") != "saved":
            raise VaultError(502, "save_unconfirmed")
        try:
            connection_id = str(uuid.UUID(result["connection_id"]))
        except (KeyError, ValueError, TypeError, AttributeError):
            raise VaultError(502, "save_unconfirmed") from None
        return {"connection_id": connection_id,
                "ref": f"vault://{metadata['service']}/{metadata['account']}"}
