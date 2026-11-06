"""Fixed operation registry: destinations, output schemas, payload rules.

Port of src/registry.ts (UNIFICATION-PLAN §4 rows 8-9). Callers can never
supply URLs, paths, headers or scripts — only registered operation ids.
"""
from __future__ import annotations

import re

from .errors import VaultError

STORAGE_ONLY_ORIGIN = "https://storage-only.vault.local"
CREDENTIAL_TYPES = {"api_key", "password", "oauth", "external_reference"}

# Fixed registered operations. mock.* targets the local synthetic mock only.
OPERATIONS = {
    "mock.account_summary": {
        "service_id": "synthetic-mock",
        "origin": "http://127.0.0.1:43121",
        "method": "GET",
        "path": "/v1/account/summary",
        "mock": True,
        "semantics": "read_only",
        "business_target": "authenticated-account",
        "output": {"account": {"id": str, "name": str}, "plan": str,
                   "notices": list},
    },
}
SERVICES = {
    "synthetic-mock": {"origin": "http://127.0.0.1:43121",
                       "credential_types": ["api_key"],
                       "operations": ["mock.account_summary"], "synthetic": True},
    "external-reference": {"origin": "", "credential_types": ["external_reference"],
                           "operations": [], "synthetic": False},
}
SYNTHETIC_TOKEN = re.compile(r"^synthetic_[A-Za-z0-9_-]+$")

_SAFE_STRING = re.compile(r"^[\x21-\x7e]{1,16384}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_TICKET = re.compile(r"^[a-f0-9]{32}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")


def is_safe_name(value: object) -> bool:
    """Printable single-line name (service/account identifiers)."""
    return isinstance(value, str) and bool(_SAFE_NAME.fullmatch(value))


def is_safe_account(value: object) -> bool:
    """An account alias may be an email or a non-ASCII display name.
    It is metadata, not a path; reject control characters and path separators.
    """
    return (isinstance(value, str) and 1 <= len(value) <= 100 and value.strip() == value
            and all(c.isprintable() and c not in '/\\' for c in value))


# Operations a stored credential may be used for. Kept small and explicit:
# an unknown operation can never be granted, so a typo fails closed.
ALLOWED_OPERATIONS = frozenset({"chat", "completion", "embed", "read", "login", "fill"})


def validate_allowed_operations(operations: object) -> list[str]:
    """Normalize a credential's permitted operations; empty means storage only."""
    if operations is None:
        return []
    if not isinstance(operations, list) or len(operations) > 20:
        raise RegistryError("invalid_operations")
    if any(not isinstance(op, str) or op not in ALLOWED_OPERATIONS for op in operations):
        raise RegistryError("invalid_operations")
    if len(set(operations)) != len(operations):
        raise RegistryError("invalid_operations")
    return sorted(operations)


class RegistryError(VaultError):
    """Registry validation failure; a VaultError with status 400."""

    def __init__(self, code: str):
        super().__init__(400, code)


def is_safe_code(value: object) -> bool:
    return isinstance(value, str) and bool(_SAFE_CODE.match(value))


def is_ticket(value: object) -> bool:
    return isinstance(value, str) and bool(_TICKET.match(value))


def operation_metadata() -> list[dict]:
    return [{"id": op_id, "service_id": op["service_id"], "origin": op["origin"],
             "semantics": op["semantics"], "description": f"Read {op['business_target']} via fixed destination."}
            for op_id, op in OPERATIONS.items()]


def services_metadata() -> list[dict]:
    return [{"service_id": sid, **data} for sid, data in SERVICES.items()]


def validate_save_payload(payload: object) -> dict:
    """Storage-only passwords plus registered-service entries; strict fields."""
    if not isinstance(payload, dict):
        raise RegistryError("invalid_draft")
    allowed = {"mode", "label", "service_id", "credential_type", "account_alias",
               "secret", "origin", "environment", "granted_operations"}
    if set(payload) - allowed or "mode" not in payload:
        raise RegistryError("invalid_draft")
    if payload["mode"] != "create":
        raise RegistryError("invalid_draft")  # replace flow arrives with P4 versioning
    if payload.get("environment") != "local":
        raise RegistryError("invalid_draft")
    for field in ("label", "service_id", "account_alias", "origin"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip() or len(value) > 2048:
            raise RegistryError("invalid_draft")
    secret = payload.get("secret")
    if not isinstance(secret, str) or not secret or len(secret) > 65536:
        raise RegistryError("invalid_draft")
    ops = payload.get("granted_operations")
    if not isinstance(ops, list) or len(ops) > 20 or not all(isinstance(o, str) and o for o in ops) \
            or len(set(ops)) != len(ops):
        raise RegistryError("invalid_draft")
    if payload["credential_type"] == "password" and payload["origin"] == STORAGE_ONLY_ORIGIN \
            and not ops and payload["service_id"].strip():
        return payload  # storage-only: identity, never a dispatch destination
    service = SERVICES.get(payload["service_id"])
    if not service:
        raise RegistryError("unregistered_service_or_scope")
    if payload["origin"] != service["origin"] or payload["credential_type"] not in service["credential_types"]:
        raise RegistryError("unregistered_service_or_scope")
    if any(op not in service["operations"] for op in ops):
        raise RegistryError("unregistered_service_or_scope")
    if payload["credential_type"] == "api_key":
        if service["synthetic"] and not SYNTHETIC_TOKEN.match(secret):
            raise RegistryError("synthetic_token_required")
        if not _SAFE_STRING.match(secret):
            raise RegistryError("invalid_api_token")
    return payload


def validate_execution_input(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise RegistryError("invalid_operation")
    required = {"request_id", "connection_id", "operation_id",
                "expected_record_version", "args"}
    if set(payload) != required:
        raise RegistryError("invalid_operation")
    if not is_ticket(payload["request_id"]):
        raise RegistryError("invalid_operation")
    if not isinstance(payload["connection_id"], str) or len(payload["connection_id"]) != 36:
        raise RegistryError("invalid_operation")
    operation = OPERATIONS.get(payload["operation_id"])
    if not operation:
        raise RegistryError("unknown_operation")
    version = payload["expected_record_version"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise RegistryError("invalid_operation")
    if payload["args"] != {}:
        raise RegistryError("invalid_operation")
    return payload


def validate_operation_output(operation_id: str, output: object) -> dict:
    schema = OPERATIONS[operation_id]["output"]
    if not isinstance(output, dict) or set(output) != set(schema):
        raise RegistryError("upstream_response_denied")

    def check(value: object, kind: object) -> None:
        if isinstance(kind, dict):
            if not isinstance(value, dict) or set(value) != set(kind):
                raise RegistryError("upstream_response_denied")
            for key, sub_kind in kind.items():
                check(value[key], sub_kind)
            return
        if kind is list:
            if not isinstance(value, list):
                raise RegistryError("upstream_response_denied")
        elif not isinstance(value, kind) or isinstance(value, bool) and kind is not bool:
            raise RegistryError("upstream_response_denied")

    for key, kind in schema.items():
        check(output[key], kind)
    return output


def redact_secrets(value: object, secrets: list[str]) -> object:
    """Replace any secret occurrence (raw/encoded/base64) in returned data."""
    variants = []
    for secret in secrets:
        if not secret:
            continue
        import base64 as _b64
        import urllib.parse as _up
        variants += [secret, _up.quote(secret, safe=""), _b64.b64encode(secret.encode()).decode()]
    def walk(item):
        if isinstance(item, str):
            for variant in variants:
                item = item.replace(variant, "[REDACTED]")
            return item
        if isinstance(item, list):
            return [walk(entry) for entry in item]
        if isinstance(item, dict):
            return {walk(key): walk(entry) for key, entry in item.items()}
        return item
    return walk(value)
