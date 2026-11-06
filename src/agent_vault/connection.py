"""One connection owner used by browser and MCP transports.

Only this process owns Vault or Remote objects. Selection is staged; a new
connection becomes active only after successful browser authentication.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from . import registry
from .errors import VaultError
from .device_store import DeviceStore
from .guard import GuardError
from .remote import Remote
from .vault import Vault

ADMIN = {"owner_id": "local", "principal_id": "admin", "client_id": "management"}


class ConnectionCore:
    def __init__(self, directory: str, *, server_url: str | None = None,
                 allow_loopback_http: bool = False):
        self.directory = os.path.abspath(directory)
        self.lock = threading.RLock()
        self.allow_loopback_http = allow_loopback_http
        self.active: Vault | Remote | None = None
        self.candidate: Vault | Remote | str | None = None
        self.candidate_mode = ""
        self.selection_id: str | None = None
        self.phase = "needs_target"
        self.last_error: str | None = None
        self.generation = 0
        self.deadline = 0.0
        self.requests: dict[str, dict] = {}
        self.export_dir = os.path.join(os.path.abspath(directory) + ".connector", "exports")
        self.config_path = Path(self.directory + ".connector") / "target.json"
        self.device_store = DeviceStore(self.directory)
        self.remember_device = False
        self._restore_pending = False
        self._retry_after = 0.0
        # A completed user switch takes precedence over the installation's
        # default URL. Never force an old environment default on every restart.
        if self.config_path.exists():
            try:
                config = self._read_config()
                if "device" in config:
                    self.candidate_mode = config["mode"]
                    if self.candidate_mode == "remote":
                        self.candidate = Remote(config["server_url"], allow_loopback_http=self.allow_loopback_http)
                    elif self.candidate_mode == "local":
                        self.candidate = Vault(self.directory)
                    else:
                        raise ValueError()
                    self.remember_device = True
                    self._restore_pending = True
                    self.phase = "reconnecting"
                    self.selection_id = secrets.token_hex(16)
                    # Restore only on first use after the HTTP listener has
                    # started; startup must not wait for a remote login.
                    return
                if config.get("mode") == "local":
                    self.select("local")
                    return
                if config.get("mode") != "remote" or not isinstance(config.get("server_url"), str):
                    raise ValueError()
                server_url = config["server_url"]
            except (OSError, ValueError, VaultError, GuardError):
                self.last_error = "saved_target_unavailable"
                return
        if server_url:
            try:
                self.select("remote", server_url)
            except VaultError as error:
                self.last_error = error.code

    def _read_config(self) -> dict:
        from .guard import platform_guard
        platform_guard().check_file(str(self.config_path))
        data = self.config_path.read_bytes()
        if len(data) > 65536:
            raise VaultError(409, "remembered_device_unavailable")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise VaultError(409, "remembered_device_unavailable")
        return value

    def _write_config(self, config: dict) -> None:
        from .guard import platform_guard
        guard = platform_guard()
        guard.ensure_private_directory(str(self.config_path.parent), create=True)
        temp = self.config_path.with_name("target-" + secrets.token_hex(8) + ".json")
        guard.create_private_file(str(temp), json.dumps(config).encode())
        try:
            os.replace(temp, self.config_path)
        except OSError:
            temp.unlink(missing_ok=True)
            raise VaultError(503, "target_config_unavailable") from None

    def _forget_device(self) -> None:
        if self.config_path.exists():
            config = self._read_config()
            if "device" in config:
                config.pop("device")
                self._write_config(config)
        self.remember_device = False
        self._restore_pending = False

    def _credentials_for(self, backend: Vault | Remote) -> dict:
        try:
            config = self._read_config()
        except (OSError, ValueError, GuardError):
            raise VaultError(409, "remembered_device_unavailable") from None
        mode = "remote" if isinstance(backend, Remote) else "local"
        url = backend.url if isinstance(backend, Remote) else None
        if config.get("mode") != mode or config.get("server_url") != url:
            raise VaultError(409, "remembered_device_unavailable")
        return self.device_store.open(mode, url, config.get("device"))

    def _renew_remote(self, backend: Remote) -> None:
        if time.monotonic() < self._retry_after:
            raise VaultError(503, "reconnect_pending")
        self._retry_after = time.monotonic() + 5
        try:
            credentials = self._credentials_for(backend)
            backend.login(credentials["username"], credentials["password"])
            credentials.clear()
            self.last_error = None
            self._retry_after = 0
            if self.active is backend and self.candidate is None:
                self.phase = "ready"
        except VaultError as error:
            if error.code in ("login_rejected", "session_expired", "remembered_device_unavailable"):
                self.logout()
                self.last_error = "remembered_login_rejected" if error.code == "login_rejected" else error.code
                raise VaultError(401, "session_expired") from None
            self.last_error = error.code
            self.phase = "reconnecting"
            raise

    def _restore(self) -> None:
        if not self._restore_pending or self.candidate is None:
            return
        backend = self.candidate
        try:
            if isinstance(backend, Remote):
                self._renew_remote(backend)
                backend.renew = lambda: self._renew_remote(backend)
            elif isinstance(backend, Vault):
                credentials = self._credentials_for(backend)
                backend.unlock(credentials["password"])
                credentials.clear()
            else:
                raise VaultError(409, "remembered_device_unavailable")
            self.active = backend
            self.candidate = None
            self.selection_id = None
            self.phase = "ready"
            self.deadline = float("inf")
            self._restore_pending = False
            self.last_error = None
        except VaultError as error:
            if error.code in ("invalid_passphrase", "remembered_device_unavailable", "session_expired"):
                self._forget_device()
                self.candidate = backend
                self.candidate_mode = "remote" if isinstance(backend, Remote) else "local"
                self.phase = "needs_login" if isinstance(backend, Remote) else "needs_unlock"
                self.selection_id = secrets.token_hex(16)
                self.last_error = "remembered_login_rejected"
            else:
                self.last_error = error.code

    def select(self, mode: str, server_url: str | None = None) -> dict:
        with self.lock:
            # A failed selection does not replace the active connection.
            self.last_error = None
            if mode == "remote":
                remote = Remote(server_url, allow_loopback_http=self.allow_loopback_http)
                try:
                    info = remote.probe()
                except VaultError as error:
                    self.last_error = error.code
                    raise
                self.candidate = remote
                self.phase = ("needs_create" if info["initialization"] == "uninitialized"
                              else "needs_login")
            elif mode == "local":
                database = os.path.join(self.directory, "vault.sqlite")
                if not os.path.exists(database):
                    if os.path.isdir(self.directory) and os.listdir(self.directory):
                        raise VaultError(409, "local_directory_not_empty")
                    self.candidate, self.phase = "new_local", "needs_create"
                else:
                    try:
                        vault = self.active if isinstance(self.active, Vault) else Vault(self.directory)
                        vault.epoch  # metadata/schema check, not merely path existence
                    except (VaultError, GuardError, OSError, sqlite3.Error):
                        # Fail closed; never offer to overwrite a broken database.
                        raise VaultError(409, "local_backend_unavailable") from None
                    self.candidate, self.phase = vault, "needs_unlock"
            else:
                raise VaultError(400, "invalid_target")
            self._restore_pending = False
            self._retry_after = 0
            self.candidate_mode = mode
            self.selection_id = secrets.token_hex(16)
            return self.status()

    def _ready(self) -> Vault | Remote:
        self._restore()
        if self.active is None:
            raise VaultError(401, "login_required")
        if not self.remember_device and time.monotonic() >= self.deadline:
            self.logout(forget=False)
            raise VaultError(401, "session_expired")
        if isinstance(self.active, Remote) and not self.active.authenticated:
            if self.remember_device:
                self._renew_remote(self.active)
            else:
                self.logout(forget=False)
                raise VaultError(401, "session_expired")
        if isinstance(self.active, Vault) and not self.active.unlocked:
            raise VaultError(423, "vault_locked")
        return self.active

    def status(self) -> dict:
        with self.lock:
            self._restore()
            ready = False
            if self.active is not None:
                try:
                    self._ready()
                    ready = True
                except VaultError:
                    pass
            candidate = self.candidate
            active = self.active
            value = {"phase": self.phase, "connected": ready, "unlocked": ready,
                     "mode": "remote" if isinstance(active, Remote) else "local" if active else None,
                     "server_url": active.url if isinstance(active, Remote) else None,
                     "candidate_mode": self.candidate_mode or None,
                     "selection_id": self.selection_id,
                     "candidate_url": candidate.url if isinstance(candidate, Remote) else None,
                     "initialization": candidate.initialization if isinstance(candidate, Remote)
                         else "uninitialized" if candidate == "new_local" else "ready" if candidate else "unknown",
                     "creation_supported": bool(candidate.setup_path) if isinstance(candidate, Remote)
                         else candidate == "new_local",
                     "generation": self.generation,
                     "remember_device": self.remember_device,
                     "session_remaining_s": None if self.remember_device else
                         max(0, int(self.deadline - time.monotonic())) if ready else 0}
            if self.last_error:
                value["error"] = self.last_error
            return value

    def authenticate(self, action: str, data: dict) -> dict:
        with self.lock:
            candidate = self.candidate
            password = data.get("passphrase")
            remember = data.get("remember_device", True)
            if type(remember) is not bool:
                raise VaultError(400, "invalid_remember_device")
            if candidate is None:
                raise VaultError(409, "select_target_first")
            if not self.selection_id or data.get("selection_id") != self.selection_id:
                raise VaultError(409, "target_selection_changed")
            if action == "create":
                if self.phase != "needs_create":
                    raise VaultError(409, "creation_not_required")
                if candidate == "new_local":
                    if not isinstance(password, str) or password != data.get("confirm"):
                        raise VaultError(400, "passphrase_mismatch")
                    Vault.initialize(self.directory, password)
                    candidate = Vault(self.directory)
                    # Creation is now real even if unlock subsequently fails.
                    self.candidate = candidate
                    self.phase = "needs_unlock"
                    candidate.unlock(password)
                elif isinstance(candidate, Remote):
                    candidate.create(data.get("username"), password, data.get("confirm"))
            elif action == "login":
                if isinstance(candidate, Remote):
                    candidate.login(data.get("username"), password)
                elif isinstance(candidate, Vault):
                    if not isinstance(password, str):
                        raise VaultError(400, "invalid_passphrase")
                    candidate.unlock(password)
                else:
                    raise VaultError(409, "creation_required")
            else:
                raise VaultError(400, "invalid_action")
            # Target and protected device credentials commit together in one
            # atomic file replacement. No plaintext password/token is persisted.
            config = {"mode": "remote" if isinstance(candidate, Remote) else "local",
                      "server_url": candidate.url if isinstance(candidate, Remote) else None}
            if remember:
                config["device"] = self.device_store.protect(config["mode"], config["server_url"],
                    candidate.username if isinstance(candidate, Remote) else None, password)
            self._write_config(config)
            old = self.active
            self.active = candidate
            if old is not None and old is not candidate:
                if isinstance(old, Vault):
                    old.lock()
                else:
                    old.clear()
            self.generation += 1
            self.requests.clear()
            self.remember_device = remember
            self._restore_pending = False
            self._retry_after = 0
            self.deadline = float("inf") if remember else time.monotonic() + 3600
            if isinstance(candidate, Remote):
                candidate.renew = (lambda: self._renew_remote(candidate)) if remember else None
            self.candidate = None
            self.selection_id = None
            self.phase = "ready"
            self.last_error = None
            return self.status()

    def cancel_selection(self) -> dict:
        with self.lock:
            if isinstance(self.candidate, Remote):
                self.candidate.clear()
            self.candidate = None
            self.selection_id = None
            self.phase = "ready" if self.active else "needs_target"
            self.last_error = None
            return self.status()

    def close(self) -> None:
        """Process shutdown clears memory but preserves remembered devices."""
        self.logout(forget=False)

    def logout(self, *, forget: bool = True) -> dict:
        with self.lock:
            if forget:
                self._forget_device()
            else:
                self._restore_pending = False
            active = self.active
            if isinstance(active, Vault):
                active.lock()
            elif isinstance(active, Remote):
                active.clear()
            self.active = None
            self.candidate = active
            self.selection_id = secrets.token_hex(16) if active else None
            self.phase = "needs_login" if isinstance(active, Remote) else "needs_unlock" if active else "needs_target"
            self.requests.clear()
            self.deadline = 0
            self.generation += 1
            return {"status": "logged_out"}

    def details(self, request_id: str, principal: str | None = None) -> dict:
        item = self.requests.get(request_id)
        if not item or item["generation"] != self.generation:
            raise VaultError(404, "request_not_found")
        if principal is not None and item["principal"] != principal:
            raise VaultError(403, "forbidden")
        if item["status"] == "pending" and time.monotonic() >= item["deadline"]:
            item["status"] = "expired"
        return {key: item[key] for key in ("request_id", "service", "account", "credential_type", "status")} | {
            "expires_in": max(0, int(item["deadline"] - time.monotonic())),
            **({"ref": item["ref"]} if "ref" in item else {})}

    def pending(self) -> list[dict]:
        with self.lock:
            return [detail for key in self.requests
                    if (detail := self.details(key))["status"] == "pending"]

    def complete(self, request_id: str, secret: object) -> dict:
        with self.lock:
            backend = self._ready()
            details = self.details(request_id)
            if details["status"] != "pending":
                raise VaultError(409, "request_not_pending")
            if not isinstance(secret, str) or not 1 <= len(secret) <= 65536:
                raise VaultError(400, "invalid_credential")
            item = self.requests[request_id]
            # Claim before any I/O; uncertain remote writes are never retried.
            item["status"] = "processing"
            try:
                if isinstance(backend, Remote):
                    saved = backend.save(item, secret, item.get("allowed_operations"))
                else:
                    saved = backend.complete_enrollment(item["backend_request_id"], secret,
                        item["credential_type"], item.get("allowed_operations"))
            except VaultError as error:
                item["status"] = "save_unconfirmed"
                if error.code == "session_expired":
                    self.logout()
                raise
            item["status"], item["ref"] = "captured", saved["ref"]
            return self.details(request_id)

    def decline(self, request_id: str, principal: str | None = None) -> dict:
        with self.lock:
            detail = self.details(request_id, principal)
            if detail["status"] != "pending":
                raise VaultError(409, "request_not_pending")
            item = self.requests[request_id]
            if isinstance(self.active, Vault):
                self.active.decline_enrollment(item["backend_request_id"])
            item["status"] = "declined"
            return self.details(request_id, principal)

    def consume(self, connection_id: str, operation: str, caller: str = "agent") -> dict:
        """Controlled in-process credential use. Never exposed as an MCP tool."""
        with self.lock:
            backend = self._ready()
            if isinstance(backend, Remote):
                metadata = backend.credential_metadata(connection_id)
                if operation not in metadata["allowed_operations"]:
                    raise VaultError(403, "operation_denied")
                return backend.consume(connection_id, operation, caller)
            raise VaultError(403, "remote_execution_unsupported")

    def credential_scope(self, connection_id: str) -> dict:
        """Allowed operations for one credential; metadata only."""
        with self.lock:
            backend = self._ready()
            if isinstance(backend, Remote):
                return backend.credential_metadata(connection_id)
            row = backend._connection_row(connection_id)
            return {"connection_id": row["connection_id"], "service_id": row["service_id"],
                    "account_alias": row["account_alias"],
                    "credential_type": row["credential_type"],
                    "allowed_operations": json.loads(row["granted_operations"])}

    def consume_local(self, connection_id: str, operation: str, caller: str = "agent") -> dict:
        """Use a locally stored credential in-process; never returns to MCP."""
        with self.lock:
            backend = self._ready()
            if not isinstance(backend, Vault):
                raise VaultError(403, "remote_execution_unsupported")
            row = backend._connection_row(connection_id)
            allowed = json.loads(row["granted_operations"])
            if operation not in allowed:
                raise VaultError(403, "operation_denied")
            secret = backend.with_token(connection_id, lambda token: token)
            return {"secret": secret, "service_id": row["service_id"],
                    "account_alias": row["account_alias"]}

    def export_credential(self, connection_id: str, operation: str, filename: str,
                          destination: str | None = None, fmt: str = "raw") -> dict:
        """Write a stored secret to a local file and return only its path.

        The plaintext goes straight to the file; it never enters an MCP tool
        result. The caller has already accepted that an agent with filesystem
        access can read the exported file afterwards.
        """
        with self.lock:
            if fmt not in ("raw", "json"):
                raise VaultError(400, "invalid_format")
            if (not isinstance(filename, str) or not filename or len(filename) > 128
                    or any(c in '<>:"/\\|?*' or ord(c) < 32 for c in filename)
                    or filename.startswith(".") or filename.endswith((".", " "))
                    or filename.split(".", 1)[0].upper() in
                        {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],
                         *[f"LPT{i}" for i in range(1, 10)]}):
                raise VaultError(400, "invalid_filename")
            if destination is not None:
                if (not isinstance(destination, str) or not os.path.isabs(destination)
                        or destination.startswith(("\\\\", "//"))):
                    raise VaultError(400, "invalid_destination")
                folder = os.path.abspath(destination)
                if os.name == "nt" and folder.startswith("\\\\"):
                    raise VaultError(400, "invalid_destination")
            else:
                folder = self.export_dir
            # Authentication and permission checks come first: a denied export
            # must not leave artifacts or touch any directory.
            backend = self._ready()
            if isinstance(backend, Remote):
                metadata = backend.credential_metadata(connection_id)
                if operation not in metadata["allowed_operations"]:
                    raise VaultError(403, "operation_denied")
                result = backend.consume(connection_id, operation, "exporter")
                secret = result["secret"]
                service, account = metadata["service_id"], metadata["account_alias"]
            else:
                row = backend._connection_row(connection_id)
                if operation not in json.loads(row["granted_operations"]):
                    raise VaultError(403, "operation_denied")
                secret = backend.with_token(connection_id, lambda token: token)
                service, account = row["service_id"], row["account_alias"]
            content = (json.dumps({"service": service, "account": account, "secret": secret},
                                  ensure_ascii=False, indent=2)
                       if fmt == "json" else secret)
            from .guard import platform_guard
            guard = platform_guard()
            temp_name = filename + ".partial-" + secrets.token_hex(8)
            try:
                if not os.path.isdir(folder):
                    guard.ensure_private_directory(folder, create=True)
                else:
                    guard.check_directory(folder)
                guard.create_private_file(os.path.join(folder, temp_name), content.encode())
                os.replace(os.path.join(folder, temp_name), os.path.join(folder, filename))
            except (GuardError, OSError):
                Path(folder).joinpath(temp_name).unlink(missing_ok=True)
                raise VaultError(503, "export_target_unavailable") from None
            path = os.path.join(folder, filename)
            return {"path": path, "bytes": os.path.getsize(path), "format": fmt,
                    "service_id": service, "account_alias": account,
                    "note": "Secret written to the file; it was not included in this result."}

    def call_tool(self, name: str, args: dict, auth: dict) -> dict:
        """Safe model surface; no browser auth/create/secret input actions."""
        with self.lock:
            principal = Vault._authorize(auth, admin=False)
            if name == "vault_status":
                return self.status()
            if name == "vault_select_target":
                return self.select(args.get("mode"), args.get("server_url"))
            if name == "vault_result":
                return self.details(args.get("request_id"), principal)
            if name == "vault_decline":
                return self.decline(args.get("request_id"), principal)
            backend = self._ready()
            if name == "vault_export_credential":
                return self.export_credential(args.get("connection_id"), args.get("operation"),
                                              args.get("filename"), args.get("destination"),
                                              args.get("format", "raw"))
            if name == "vault_begin_enrollment":
                if self.candidate is not None or self.last_error:
                    raise VaultError(409, "target_selection_pending")
                service, account = args.get("service"), args.get("account")
                if not registry.is_safe_name(service) or not registry.is_safe_account(account):
                    raise VaultError(400, "invalid_arguments")
                kind = args.get("credential_type", "api_key" if service in ("deepseek", "deepseek-api") else "password")
                if kind not in ("api_key", "password", "oauth", "external_reference"):
                    raise VaultError(400, "invalid_credential_type")
                if len(self.requests) >= 1000:
                    raise VaultError(429, "request_limit")
                request_id = secrets.token_hex(16)
                item = {"request_id": request_id, "service": service, "account": account,
                        "credential_type": kind, "status": "pending", "principal": principal,
                        "generation": self.generation, "deadline": time.monotonic() + 600,
                        "allowed_operations": registry.validate_allowed_operations(
                            args.get("allowed_operations"))}
                if isinstance(backend, Vault):
                    item["backend_request_id"] = backend.begin_enrollment(service, account)["request_id"]
                self.requests[request_id] = item
                return self.details(request_id, principal)
            if name in ("vault_list", "list_connections", "vault_find", "get_connection_status"):
                rows = backend.inventory() if isinstance(backend, Remote) else backend.list_connections(auth)
                if name == "vault_find":
                    return {"matches": [r for r in rows if r["service_id"] == args.get("service_id")]}
                if name == "get_connection_status":
                    matches = [r for r in rows if r["connection_id"] == args.get("connection_id")]
                    if not matches:
                        raise VaultError(404, "connection_not_found")
                    return matches[0]
                return {"connections": rows}
            if isinstance(backend, Remote):
                if name == "list_operations":
                    return {"operations": [], "next_action": "Remote controlled execution is not supported by this service contract."}
                raise VaultError(403, "remote_execution_unsupported")
            if name == "list_operations":
                return {"operations": registry.operation_metadata()}
            if name == "prepare_request":
                return backend.prepare_request(auth, args.get("operation_name"))
            if name == "execute_operation":
                return backend.execute_operation(auth, dict(args, args={}))
            if name == "get_operation_status":
                return backend.operation_status(auth, args.get("request_id"), args.get("operation_id"))
            raise VaultError(400, "invalid_tool_request")
