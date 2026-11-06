"""Unified vault core: initialization, unlock, drafts/approvals, credentials,
durable execution journal and enrollment requests.

Port of src/vault.ts invariants (UNIFICATION-PLAN §4 rows 2-7, 10-11):
- exclusive empty-directory initialization; execution key hash; independent
  request-signing key; loss of either fails closed;
- authentication/unlock separation, failure lockout, epoch bump on lock that
  invalidates the in-memory master key;
- drafts hold secrets in memory only, cards are redacted, approval tokens are
  single-use, saves are record-CAS'd transactions;
- the requests journal is durable: accepted -> dispatching -> terminal;
  outcome_unknown is never re-dispatched and replays never hit upstream;
- plaintext is wiped where the runtime allows; JSON strings are never logged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

from . import registry
from .crypto import CryptoError, derive_key, seal, unseal
from .errors import VaultError
from .guard import GuardError, platform_guard

__all__ = ["Vault", "VaultError"]

DAY = 86400
RETAIN_DAYS = 7
DRAFT_TTL = 300
ENROLLMENT_TTL = 600
MAX_UNLOCK_FAILURES = 5
LOCKOUT_SECONDS = 900
CONTEXT = "agent-vault:v1:"


def _now() -> int:
    return int(time.time())


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _connect(directory: str) -> sqlite3.Connection:
    connection = sqlite3.connect(os.path.join(directory, "vault.sqlite"), timeout=10)
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_meta (
  id INTEGER PRIMARY KEY CHECK (id=1), salt TEXT NOT NULL, verifier TEXT NOT NULL,
  execution_hash TEXT NOT NULL, unlock_failures INTEGER NOT NULL DEFAULT 0,
  unlock_blocked_until INTEGER NOT NULL DEFAULT 0, security_epoch INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS credentials (
  connection_id TEXT PRIMARY KEY, owner TEXT NOT NULL, service_id TEXT NOT NULL,
  account_alias TEXT NOT NULL, credential_type TEXT NOT NULL, encrypted TEXT NOT NULL,
  encryption_context TEXT NOT NULL, status TEXT NOT NULL, record_version INTEGER NOT NULL,
  status_version INTEGER NOT NULL, granted_operations TEXT NOT NULL,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_verified_at INTEGER);
CREATE TABLE IF NOT EXISTS consumed_drafts (
  draft_id TEXT NOT NULL, epoch INTEGER NOT NULL, request_id TEXT NOT NULL,
  consumed_at INTEGER NOT NULL, PRIMARY KEY (draft_id, epoch));
CREATE TABLE IF NOT EXISTS requests (
  request_id TEXT NOT NULL, operation_name TEXT NOT NULL, owner TEXT NOT NULL,
  principal_id TEXT NOT NULL, registered_at INTEGER NOT NULL, retain_until INTEGER NOT NULL,
  canonical_encrypted TEXT, state TEXT NOT NULL, connection_id TEXT,
  result_json TEXT, dispatched_at INTEGER, PRIMARY KEY (request_id, operation_name));
CREATE TABLE IF NOT EXISTS enrollment_requests (
  request_id TEXT PRIMARY KEY, service TEXT NOT NULL, account TEXT NOT NULL,
  prompt TEXT NOT NULL, status TEXT NOT NULL, ref TEXT, timeout_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS agent_grants (
  agent_id TEXT NOT NULL, operation_id TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, operation_id));
"""


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


class Vault:
    def __init__(self, directory: str):
        self.directory = platform_guard().check_directory(directory)
        self.signing_key = self._load_signing_key()
        self._key: _Key | None = None
        self._key_epoch = 0
        self._drafts: dict[str, dict] = {}
        self._generation = 0

    # -- initialization ---------------------------------------------------
    @staticmethod
    def initialize(directory: str, passphrase: str) -> None:
        if not isinstance(passphrase, str) or len(passphrase) < 12 or len(passphrase) > 1024:
            raise VaultError(400, "invalid_passphrase")
        guard = platform_guard()
        directory = guard.ensure_private_directory(directory, create=True)
        if os.listdir(directory):
            raise VaultError(409, "directory_not_empty")
        execution = secrets.token_hex(32)
        signing = os.urandom(32)
        guard.create_private_file(os.path.join(directory, "execution.key"), execution.encode())
        guard.create_private_file(os.path.join(directory, "request-signing.key"), signing)
        salt = os.urandom(32)
        verifier = hashlib.sha256(derive_key(passphrase, salt)).hexdigest()
        connection = _connect(directory)
        try:
            connection.executescript(_SCHEMA)
            with connection:
                connection.execute(
                    "INSERT INTO vault_meta(id,salt,verifier,execution_hash) VALUES(1,?,?,?)",
                    (salt.hex(), verifier, hashlib.sha256(execution.encode()).hexdigest()))
        finally:
            connection.close()

    def _load_signing_key(self) -> bytes:
        path = os.path.join(self.directory, "request-signing.key")
        try:
            data = platform_guard().check_file(path)
        except GuardError:
            raise VaultError(500, "signing_key_missing") from None
        with open(data, "rb") as stream:
            key = stream.read(32)
        if len(key) != 32 or os.stat(data).st_size != 32:
            raise VaultError(500, "signing_key_invalid")
        return key

    # -- meta / epochs ----------------------------------------------------
    def _meta(self, connection: sqlite3.Connection) -> dict:
        row = connection.execute("SELECT salt,verifier,execution_hash,unlock_failures,"
                                 "unlock_blocked_until,security_epoch FROM vault_meta WHERE id=1").fetchone()
        if not row:
            raise VaultError(500, "vault_meta_missing")
        keys = ("salt", "verifier", "execution_hash", "unlock_failures",
                "unlock_blocked_until", "security_epoch")
        return dict(zip(keys, row))

    def _bump_epoch(self, connection: sqlite3.Connection) -> int:
        connection.execute("UPDATE vault_meta SET security_epoch=security_epoch+1,"
                           "unlock_failures=0, unlock_blocked_until=0 WHERE id=1")
        return self._meta(connection)["security_epoch"]

    @property
    def epoch(self) -> int:
        connection = _connect(self.directory)
        try:
            return self._meta(connection)["security_epoch"]
        finally:
            connection.close()

    @property
    def unlocked(self) -> bool:
        return self._key is not None and self._key_epoch == self.epoch

    def _require_unlocked(self) -> _Key:
        if not self.unlocked:
            raise VaultError(423, "vault_locked")
        return self._key

    # -- unlock / lock ----------------------------------------------------
    def unlock(self, passphrase: str) -> None:
        connection = _connect(self.directory)
        try:
            # Failure counters must COMMIT before the raise; raising inside a
            # `with connection` block would roll the counter back (lockout
            # would never persist). Commit explicitly, then signal.
            connection.execute("BEGIN IMMEDIATE")
            meta = self._meta(connection)
            if meta["unlock_blocked_until"] > _now():
                connection.rollback()
                raise VaultError(429, "unlock_blocked")
            candidate = derive_key(passphrase, bytes.fromhex(meta["salt"]))
            if not hmac.compare_digest(hashlib.sha256(candidate).hexdigest(), meta["verifier"]):
                failures = meta["unlock_failures"] + 1
                blocked = _now() + LOCKOUT_SECONDS if failures >= MAX_UNLOCK_FAILURES else 0
                connection.execute("UPDATE vault_meta SET unlock_failures=?,unlock_blocked_until=? WHERE id=1",
                                   (failures, blocked))
                connection.commit()
                raise VaultError(403, "invalid_passphrase")
            # Successful unlock resets the failure counters; the epoch bumps
            # only on lock() (plan §4: epoch increment aborts in-flight work).
            connection.execute("UPDATE vault_meta SET unlock_failures=0,"
                               " unlock_blocked_until=0 WHERE id=1")
            connection.commit()
        finally:
            connection.close()
        # Reuse the key already derived for verification — never scrypt twice.
        self._key = bytearray(candidate)
        self._key_epoch = self.epoch
        self._generation += 1

    def lock(self) -> None:
        connection = _connect(self.directory)
        try:
            with connection:
                self._bump_epoch(connection)
        finally:
            connection.close()
        if self._key is not None:
            for index in range(len(self._key)):
                self._key[index] = 0
            self._key = None
        self._drafts.clear()
        self._generation += 1

    # -- authorities ------------------------------------------------------
    @staticmethod
    def _authorize(auth: dict, *, admin: bool) -> str:
        if not isinstance(auth, dict):
            raise VaultError(403, "forbidden")
        owner, principal, client = auth.get("owner_id"), auth.get("principal_id"), auth.get("client_id")
        if owner != "local" or not isinstance(principal, str) or not principal:
            raise VaultError(403, "forbidden")
        if admin and (principal != "admin" or client != "management"):
            raise VaultError(403, "forbidden")
        if not admin and (client != "execution" or principal == "admin"):
            raise VaultError(403, "forbidden")
        return principal

    @staticmethod
    def _agent_id(principal: str) -> str:
        return principal[len("agent:"):] if principal.startswith("agent:") else principal

    @staticmethod
    def _valid_agent_id(agent_id: object) -> bool:
        return isinstance(agent_id, str) and 0 < len(agent_id) <= 64 \
            and all(0x20 < ord(character) < 0x7F for character in agent_id)

    # -- per-agent authorization (P4) --------------------------------------
    def grant_agent(self, auth: dict, agent_id: str, operation_ids: list[str]) -> dict:
        self._authorize(auth, admin=True)
        if not self._valid_agent_id(agent_id):
            raise VaultError(400, "invalid_agent_id")
        if operation_ids == "*":
            operation_ids = ["*"]
        if not isinstance(operation_ids, list) or not operation_ids or len(operation_ids) > 20 \
                or any(not isinstance(op, str) or (op != "*" and op not in registry.OPERATIONS)
                       for op in operation_ids):
            raise VaultError(400, "unknown_operation")
        connection = _connect(self.directory)
        try:
            with connection:
                connection.executemany("INSERT OR IGNORE INTO agent_grants VALUES(?,?,?)",
                                       [(agent_id, op, _now()) for op in operation_ids])
        finally:
            connection.close()
        return {"agent_id": agent_id, "granted": sorted(set(operation_ids))}

    def revoke_agent(self, auth: dict, agent_id: str, operation_ids: list[str] | None = None) -> dict:
        self._authorize(auth, admin=True)
        if not self._valid_agent_id(agent_id):
            raise VaultError(400, "invalid_agent_id")
        connection = _connect(self.directory)
        try:
            with connection:
                if operation_ids is None:
                    connection.execute("DELETE FROM agent_grants WHERE agent_id=?", (agent_id,))
                    return {"agent_id": agent_id, "revoked": "all"}
                if not isinstance(operation_ids, list) or not operation_ids or len(operation_ids) > 20 \
                        or any(not isinstance(op, str) or not op for op in operation_ids):
                    raise VaultError(400, "unknown_operation")
                connection.executemany("DELETE FROM agent_grants WHERE agent_id=? AND operation_id=?",
                                       [(agent_id, op) for op in operation_ids])
        finally:
            connection.close()
        return {"agent_id": agent_id, "revoked": sorted(set(operation_ids))}

    def list_agents(self, auth: dict) -> list[dict]:
        self._authorize(auth, admin=True)
        connection = _connect(self.directory)
        try:
            rows = connection.execute("SELECT agent_id, operation_id FROM agent_grants"
                                      " ORDER BY agent_id, operation_id").fetchall()
        finally:
            connection.close()
        grouped: dict[str, list[str]] = {}
        for agent_id, operation_id in rows:
            grouped.setdefault(agent_id, []).append(operation_id)
        return [{"agent_id": agent_id, "operations": operations}
                for agent_id, operations in grouped.items()]

    def agent_allowed(self, principal: str, operation_id: str) -> bool:
        """Fail-closed per-agent authorization: no grant row means no execution."""
        if not isinstance(principal, str):
            return False
        agent_id = self._agent_id(principal)
        if not self._valid_agent_id(agent_id):
            return False
        connection = _connect(self.directory)
        try:
            row = connection.execute(
                "SELECT 1 FROM agent_grants WHERE agent_id=? AND operation_id IN (?, '*')",
                (agent_id, operation_id)).fetchone()
        finally:
            connection.close()
        return row is not None

    # -- drafts / approval / save ----------------------------------------
    def create_draft(self, auth: dict, payload: dict) -> dict:
        self._authorize(auth, admin=True)
        self._require_unlocked()
        payload = registry.validate_save_payload(payload)
        if self.epoch != self._key_epoch:
            raise VaultError(423, "vault_locked")
        draft_id = secrets.token_urlsafe(16)
        card = {key: value for key, value in payload.items() if key != "secret"}
        self._drafts[draft_id] = {"payload": payload, "version": 1,
                                  "epoch": self.epoch, "expires": _now() + DRAFT_TTL,
                                  "approval": None}
        return {"draft_id": draft_id, "draft_version": 1, "card": card}

    def approve_draft(self, auth: dict, draft_id: str, draft_version: int) -> dict:
        self._authorize(auth, admin=True)
        draft = self._drafts.get(draft_id)
        if not draft or draft["expires"] <= _now() or draft["epoch"] != self.epoch:
            self._drafts.pop(draft_id, None)
            raise VaultError(410, "draft_expired")
        if draft_version != draft["version"] or draft["approval"] is not None:
            raise VaultError(409, "draft_conflict")
        draft["approval"] = secrets.token_urlsafe(32)
        return {"approval_token": draft["approval"], "draft_version": draft["version"]}

    def save_approved(self, auth: dict, data: dict) -> dict:
        self._authorize(auth, admin=True)
        key = self._require_unlocked()
        required = {"request_id", "draft_id", "draft_version", "approval_token", "payload"}
        if not isinstance(data, dict) or set(data) != required:
            raise VaultError(400, "invalid_draft")
        draft = self._drafts.get(data["draft_id"])
        if not draft or draft["expires"] <= _now() or draft["epoch"] != self.epoch:
            self._drafts.pop(data["draft_id"], None)
            # Distinguish single-use replay (already consumed) from expiry.
            probe = _connect(self.directory)
            try:
                consumed = probe.execute(
                    "SELECT 1 FROM consumed_drafts WHERE draft_id=?",
                    (data["draft_id"],)).fetchone()
            finally:
                probe.close()
            if consumed:
                raise VaultError(409, "draft_conflict")
            raise VaultError(410, "draft_expired")
        if (data["draft_version"] != draft["version"] or not draft["approval"]
                or not hmac.compare_digest(str(data["approval_token"]), draft["approval"])):
            raise VaultError(409, "draft_conflict")
        if _canonical(data["payload"]) != _canonical(draft["payload"]):
            raise VaultError(409, "draft_conflict")
        payload = registry.validate_save_payload(data["payload"])
        connection_id = str(uuid.uuid4())
        context = CONTEXT + f"credential:local:{connection_id}"
        connection = _connect(self.directory)
        try:
            # Validate everything before any INSERT: consumed_drafts marks the
            # approval spent, so it must only be written for a fully valid save.
            if not registry.is_ticket(data["request_id"]):
                raise VaultError(400, "invalid_request_id")
            sealed = seal(key, payload["secret"].encode(), context)
            with connection:
                try:
                    connection.execute("INSERT INTO consumed_drafts VALUES(?,?,?,?)",
                                       (data["draft_id"], self.epoch, data["request_id"], _now()))
                except sqlite3.IntegrityError:
                    raise VaultError(409, "draft_conflict") from None
                connection.execute(
                    "INSERT INTO credentials VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (connection_id, "local", payload["service_id"], payload["account_alias"],
                     payload["credential_type"], json.dumps(sealed), context, "active",
                     1, 1, json.dumps(payload["granted_operations"]), _now(), _now(), None))
        finally:
            connection.close()
        self._drafts.pop(data["draft_id"], None)
        return {"connection_id": connection_id, "record_version": 1, "status_version": 1,
                "status": "active"}

    # -- execution --------------------------------------------------------
    def prepare_request(self, auth: dict, operation_name: str) -> dict:
        self._authorize(auth, admin=False)
        if operation_name not in registry.OPERATIONS:
            raise VaultError(400, "unknown_operation")
        return {"request_id": secrets.token_hex(16)}

    def _connection_row(self, connection_id: str) -> dict:
        connection = _connect(self.directory)
        try:
            row = connection.execute("SELECT connection_id,owner,service_id,account_alias,"
                                     "credential_type,encrypted,encryption_context,status,"
                                     "record_version,status_version,granted_operations FROM credentials"
                                     " WHERE connection_id=?", (connection_id,)).fetchone()
        finally:
            connection.close()
        if not row:
            raise VaultError(404, "connection_not_found")
        keys = ("connection_id", "owner", "service_id", "account_alias", "credential_type",
                "encrypted", "encryption_context", "status", "record_version",
                "status_version", "granted_operations")
        return dict(zip(keys, row))

    def connection_metadata(self, row: dict) -> dict:
        return {key: row[key] for key in ("connection_id", "service_id", "account_alias",
                                          "credential_type", "status", "record_version",
                                          "status_version")}

    def list_connections(self, auth: dict) -> list[dict]:
        self._authorize(auth, admin=False)
        self._require_unlocked()
        connection = _connect(self.directory)
        try:
            rows = connection.execute("SELECT connection_id,service_id,account_alias,credential_type,"
                                      "status,record_version,status_version FROM credentials").fetchall()
        finally:
            connection.close()
        keys = ("connection_id", "service_id", "account_alias", "credential_type",
                "status", "record_version", "status_version")
        return [dict(zip(keys, row)) for row in rows]

    def with_token(self, connection_id: str, callback, expected_record_version: int | None = None,
                   operation_id: str | None = None) -> Any:
        key = self._require_unlocked()
        row = self._connection_row(connection_id)
        if row["credential_type"] == "external_reference":
            raise VaultError(403, "external_execution_unsupported")
        if row["status"] != "active":
            raise VaultError(403, "connection_unavailable")
        if expected_record_version is not None and row["record_version"] != expected_record_version:
            raise VaultError(409, "record_version_conflict")
        if operation_id and operation_id not in json.loads(row["granted_operations"]):
            raise VaultError(403, "operation_denied")
        generation = self._generation
        plaintext = bytearray()
        try:
            plaintext.extend(unseal(key, json.loads(row["encrypted"]), row["encryption_context"]))
            result = callback(plaintext.decode("utf-8"))
            if generation != self._generation or not self.unlocked:
                raise VaultError(423, "vault_locked")
            return result
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0

    def execute_operation(self, auth: dict, payload: dict) -> dict:
        principal = self._authorize(auth, admin=False)
        data = registry.validate_execution_input(payload)
        request_id, operation_id = data["request_id"], data["operation_id"]
        if not self.agent_allowed(principal, operation_id):
            raise VaultError(403, "agent_not_granted")
        definition = registry.OPERATIONS[operation_id]
        connection = _connect(self.directory)
        try:
            row = connection.execute(
                "SELECT state,result_json,owner,principal_id,retain_until,connection_id"
                " FROM requests WHERE request_id=? AND operation_name=?",
                (request_id, operation_id)).fetchone()
            if row:
                state, result_json, owner, principal_seen, retain_until, bound_connection = row
                if owner != auth["owner_id"] or principal_seen != principal:
                    raise VaultError(403, "forbidden")
                if bound_connection != data["connection_id"]:
                    raise VaultError(409, "request_conflict")
                if retain_until <= _now() and state not in ("accepted", "dispatching", "outcome_unknown"):
                    raise VaultError(410, "result_unavailable")
                if state != "failed_before_dispatch":
                    return json.loads(result_json) if result_json else {"operation": {"state": state}}
                with connection:
                    connection.execute("UPDATE requests SET state='accepted' WHERE request_id=?"
                                       " AND operation_name=?", (request_id, operation_id))
        finally:
            connection.close()
        replaying = row is not None
        connection = _connect(self.directory)
        try:
            with connection:
                if not replaying:
                    try:
                        connection.execute(
                            "INSERT INTO requests(request_id,operation_name,owner,principal_id,"
                            "registered_at,retain_until,state,connection_id)"
                            " VALUES(?,?,?,?,?,?,'accepted',?)",
                            (request_id, operation_id, auth["owner_id"], principal, _now(),
                             _now() + RETAIN_DAYS * DAY, data["connection_id"]))
                    except sqlite3.IntegrityError:
                        raise VaultError(409, "request_conflict") from None
                connection.execute("UPDATE requests SET state='dispatching' WHERE request_id=?"
                                   " AND operation_name=?", (request_id, operation_id))
        finally:
            connection.close()
        token_box: list[str] = []

        def dispatch(token: str) -> dict:
            token_box.append(token)
            return _dispatch_operation(definition, token, operation_id)

        try:
            output = self.with_token(data["connection_id"], dispatch,
                                     data["expected_record_version"], operation_id)
            result = {"operation": {"state": "succeeded",
                                    "output": registry.redact_secrets(output, token_box)}}
            state = "succeeded"
        except VaultError as error:
            # token_box non-empty means the fixed-destination request was already
            # attempted: the upstream outcome is unknowable and must never retry.
            state = "outcome_unknown" if token_box else "failed_before_dispatch"
            result = {"operation": {"state": state, "error": error.code}}
        except (CryptoError, OSError, ValueError):
            state = "outcome_unknown" if token_box else "failed_before_dispatch"
            result = {"operation": {"state": state, "error": "dispatch_denied"}}
        self._finish_request(request_id, operation_id, state, result, data["connection_id"],
                             dispatched=bool(token_box))
        return result

    def _finish_request(self, request_id: str, operation_id: str, state: str, result: dict,
                        connection_id: str, dispatched: bool) -> None:
        connection = _connect(self.directory)
        try:
            with connection:
                connection.execute(
                    "UPDATE requests SET state=?, result_json=?, connection_id=?, dispatched_at=?"
                    " WHERE request_id=? AND operation_name=?",
                    (state, json.dumps(result), connection_id,
                     _now() if dispatched else None, request_id, operation_id))
        finally:
            connection.close()

    def operation_status(self, auth: dict, request_id: str, operation_name: str) -> dict:
        principal = self._authorize(auth, admin=False)
        connection = _connect(self.directory)
        try:
            row = connection.execute("SELECT state,result_json,owner,principal_id,retain_until"
                                     " FROM requests WHERE request_id=? AND operation_name=?",
                                     (request_id, operation_name)).fetchone()
        finally:
            connection.close()
        if not row:
            raise VaultError(404, "request_not_found")
        state, result_json, owner, principal_seen, retain_until = row
        if owner != auth["owner_id"] or principal_seen != principal:
            raise VaultError(403, "forbidden")
        if retain_until <= _now() and state not in ("accepted", "dispatching", "outcome_unknown"):
            raise VaultError(410, "result_unavailable")
        return json.loads(result_json) if result_json else {"operation": {"state": state}}

    # -- enrollment (console adapter completes; MCP only coordinates) -----
    def begin_enrollment(self, service: str, account: str, prompt: str = "") -> dict:
        if not isinstance(service, str) or not registry.is_safe_name(service) \
                or not isinstance(account, str) or not registry.is_safe_account(account):
            raise VaultError(400, "invalid_arguments")
        self._require_unlocked()
        request_id = secrets.token_hex(16)
        connection = _connect(self.directory)
        try:
            with connection:
                connection.execute("INSERT INTO enrollment_requests VALUES(?,?,?,?,?,?,?,?)",
                                   (request_id, service.strip(), account.strip(),
                                    (prompt or f"Vault credential for {service}/{account}")[:512],
                                    "pending", None, _now() + ENROLLMENT_TTL, _now()))
        finally:
            connection.close()
        return {"status": "pending", "request_id": request_id,
                "next_action": "Run agent-vault enroll with this request id on the user's terminal."}

    def complete_enrollment(self, request_id: str, secret: str, credential_type: str = "password",
                            allowed_operations: list[str] | None = None) -> dict:
        """Trusted input channel only; never accept a secret through MCP tools."""
        if not isinstance(secret, str) or not secret or len(secret) > 65536:
            raise VaultError(400, "invalid_credential")
        if credential_type not in registry.CREDENTIAL_TYPES:
            raise VaultError(400, "invalid_credential_type")
        operations = registry.validate_allowed_operations(allowed_operations)
        key = self._require_unlocked()
        connection = _connect(self.directory)
        try:
            row = connection.execute("SELECT service,account,status,timeout_at FROM enrollment_requests"
                                     " WHERE request_id=?", (request_id,)).fetchone()
            if not row:
                raise VaultError(404, "request_not_found")
            service, account, status, timeout_at = row
            if status != "pending":
                raise VaultError(409, "request_not_pending")
            if timeout_at <= _now():
                self._expire_enrollment(connection, request_id)
                connection.commit()
                raise VaultError(410, "request_expired")
            connection_id = str(uuid.uuid4())
            context = CONTEXT + f"credential:local:{connection_id}"
            sealed = seal(key, secret.encode(), context)
            with connection:
                connection.execute("UPDATE enrollment_requests SET status='captured',ref=? WHERE request_id=?",
                                   (f"vault://{service}/{account}", request_id))
                connection.execute(
                    "INSERT INTO credentials VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (connection_id, "local", service, account, credential_type, json.dumps(sealed),
                     context, "active", 1, 1, json.dumps(operations), _now(), _now(), None))
            return {"status": "captured", "request_id": request_id,
                    "ref": f"vault://{service}/{account}", "connection_id": connection_id}
        finally:
            connection.close()

    def _expire_enrollment(self, connection: sqlite3.Connection, request_id: str) -> None:
        connection.execute("UPDATE enrollment_requests SET status='expired' WHERE request_id=?",
                           (request_id,))

    def enrollment_result(self, request_id: str) -> dict:
        connection = _connect(self.directory)
        try:
            row = connection.execute("SELECT status,ref,timeout_at FROM enrollment_requests"
                                     " WHERE request_id=?", (request_id,)).fetchone()
            if not row:
                raise VaultError(404, "request_not_found")
            status, ref, timeout_at = row
            if status == "pending" and timeout_at <= _now():
                with connection:
                    self._expire_enrollment(connection, request_id)
                status = "expired"
        finally:
            connection.close()
        result = {"request_id": request_id, "status": status}
        if ref:
            result["ref"] = ref
        return result

    def list_pending_enrollments(self) -> list[dict]:
        """Read-only projection for the local trusted front-end; no secrets."""
        self._require_unlocked()
        connection = _connect(self.directory)
        try:
            rows = connection.execute(
                "SELECT request_id, service, account, prompt, timeout_at FROM enrollment_requests"
                " WHERE status='pending' ORDER BY created_at").fetchall()
        finally:
            connection.close()
        return [{"request_id": row[0], "service": row[1], "account": row[2],
                 "prompt": row[3], "expires_in": max(0, row[4] - _now())} for row in rows]

    def enrollment_details(self, request_id: str) -> dict:
        """Read-only request details for the confirmation UI (anti-phishing)."""
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            raise VaultError(400, "invalid_request_id")
        connection = _connect(self.directory)
        try:
            row = connection.execute(
                "SELECT request_id, service, account, prompt, status, ref, timeout_at"
                " FROM enrollment_requests WHERE request_id=?", (request_id,)).fetchone()
        finally:
            connection.close()
        if not row:
            raise VaultError(404, "request_not_found")
        return {"request_id": row[0], "service": row[1], "account": row[2],
                "prompt": row[3], "status": row[4], "ref": row[5],
                "expires_in": max(0, row[6] - _now())}

    def decline_enrollment(self, request_id: str) -> dict:
        connection = _connect(self.directory)
        try:
            with connection:
                cursor = connection.execute(
                    "UPDATE enrollment_requests SET status='declined' WHERE request_id=? AND status='pending'",
                    (request_id,))
                if cursor.rowcount != 1:
                    raise VaultError(409, "request_not_pending")
        finally:
            connection.close()
        return {"request_id": request_id, "status": "declined"}


_current_operation: list[str] = [""]


def _dispatch_operation(definition: dict, token: str, operation_id: str) -> dict:
    """Single fixed-destination attempt; no redirects, no proxy, bounded body."""
    import urllib.request
    request = urllib.request.Request(
        definition["origin"] + definition["path"],
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=10) as response:
        raw = response.read(65537)
        if response.status != 200 or len(raw) > 65536:
            raise VaultError(502, "upstream_response_denied")
    return registry.validate_operation_output(operation_id, json.loads(raw))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
