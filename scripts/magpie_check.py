"""Minimal Magpie key check: fetch a stored key in-process, call the gateway,
print only redacted results. The key never reaches the model or the disk.

Usage:  python -B scripts/magpie_check.py [--account dsh] [--base-url URL]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src")]

from agent_vault.ipc import CoreClient  # noqa: E402

DEFAULT_BASE = None


def _mask(value: str) -> str:
    if not value:
        return "<empty>"
    if len(value) <= 8:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


def _fetch_key(data_dir: str, port: int, account: str, operation: str | None) -> tuple[str, str, str]:
    """Consume the key through the core's controlled path; never returned to stdout."""
    client = CoreClient(data_dir, port)
    listing = client.call_tool("vault_list", {}, {
        "owner_id": "local", "principal_id": "agent:magpie-check", "client_id": "execution"})
    matches = [row for row in listing.get("connections", [])
               if row.get("service_id") == "magpie" and row.get("account_alias") == account]
    if not matches:
        raise SystemExit(f"No stored magpie credential for account alias {account!r}.")
    connection_id = matches[0]["connection_id"]
    scope = client.command("consume", {"connection_id": connection_id, "scope_only": True})
    allowed = scope.get("allowed_operations") or []
    chosen = operation or next((op for op in ("chat", "completion", "read") if op in allowed), None)
    if not chosen:
        raise SystemExit(f"Credential {account!r} permits no usable operation: {allowed}.")
    if chosen not in allowed:
        raise SystemExit(f"Operation {chosen!r} is not permitted for this credential: {allowed}.")
    response = client.command("consume", {"connection_id": connection_id, "operation": chosen})
    secret = response.get("secret")
    if not isinstance(secret, str) or not secret:
        raise SystemExit("The vault did not return a usable secret for this credential.")
    return secret, connection_id, chosen


def _request(url: str, key: str, method: str = "GET", payload: dict | None = None) -> tuple[int, object]:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": "Bearer " + key, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    from agent_vault.remote import NoRedirect
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            body = response.read(262144)
            try:
                return response.status, json.loads(body)
            except ValueError:
                return response.status, {"text": body[:400].decode("utf-8", "replace")}
    except urllib.error.HTTPError as error:
        with error:
            body = error.read(4096)
            try:
                return error.code, json.loads(body)
            except ValueError:
                return error.code, {"text": body[:400].decode("utf-8", "replace")}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a stored Magpie key against the gateway.")
    parser.add_argument("--account", default="dsh", help="account alias of the stored credential")
    parser.add_argument("--base-url", default=os.environ.get("MAGPIE_BASE_URL", DEFAULT_BASE))
    parser.add_argument("--model", default="group/auto-mid")
    parser.add_argument("--prompt", default="Reply with the single word: pong")
    parser.add_argument("--operation", default=None, help="allowed operation; auto-selected when omitted")
    parser.add_argument("--data-dir", default=os.environ.get("AGENT_VAULT_DATA_DIR", os.path.expanduser("~/.agent-vault")))
    parser.add_argument("--port", type=int, default=int(os.environ.get("AGENT_VAULT_BROKER_PORT", "43122")))
    args = parser.parse_args()
    if not args.base_url:
        parser.error("Provide --base-url or MAGPIE_BASE_URL for your own gateway.")
    from agent_vault.remote import normalize_url
    from agent_vault.registry import redact_secrets
    base = normalize_url(args.base_url, allow_loopback_http=True).rstrip("/")

    try:
        key, connection_id, operation = _fetch_key(args.data_dir, args.port, args.account, args.operation)
    except SystemExit:
        raise
    except Exception as error:
        print(json.dumps({"stage": "vault", "ok": False,
                          "error": type(error).__name__, "detail": str(error)[:200]}))
        return 2

    report = {"account": args.account, "connection_id": connection_id,
              "key_fingerprint": _mask(key), "base_url": base,
              "consume_operation": operation, "checks": []}
    try:
        status, payload = _request(base + "/v1/models", key)
        models = payload.get("data") if isinstance(payload, dict) else None
        report["checks"].append({"check": "models", "http_status": status,
                                 "ok": status == 200,
                                 "model_count": len(models) if isinstance(models, list) else None})
        if status != 200:
            report["ok"] = False
            report["error"] = _summarize(payload)
            print(json.dumps(redact_secrets(report, [key]), ensure_ascii=False, indent=2))
            return 1
        listed = [item.get("id") for item in models if isinstance(item, dict)] if isinstance(models, list) else []
        report["models_sample"] = sorted(x for x in listed if isinstance(x, str))[:8]

        status, payload = _request(base + "/v1/chat/completions", key, "POST", {
            "model": args.model, "messages": [{"role": "user", "content": args.prompt}],
            "max_tokens": 16, "stream": False})
        content = ""
        if isinstance(payload, dict):
            choices = payload.get("choices")
            if isinstance(choices, list) and choices and isinstance(choices[0], dict):
                message = choices[0].get("message")
                if isinstance(message, dict):
                    content = str(message.get("content", ""))[:200]
        report["checks"].append({"check": "chat", "http_status": status, "ok": status == 200,
                                 "model": args.model, "reply": content})
        if status != 200:
            report["ok"] = False
            report["error"] = _summarize(payload)
        else:
            report["ok"] = True
        usage = payload.get("usage") if isinstance(payload, dict) else None
        if isinstance(usage, dict):
            report["usage"] = {k: usage.get(k) for k in ("prompt_tokens", "completion_tokens", "total_tokens")}
        print(json.dumps(redact_secrets(report, [key]), ensure_ascii=False, indent=2))
        return 0 if report.get("ok") else 1
    finally:
        key = ""


def _summarize(payload: object) -> str:
    """Fixed, non-secret summary of a failure body."""
    # Upstream bodies can contain credentials. Only status codes are reported.
    return "remote_error"


if __name__ == "__main__":
    raise SystemExit(main())
