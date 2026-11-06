"""Minimal OpenAI-compatible model caller backed by Agent Vault.

The API key never passes through the model context: it is either consumed
in-process from the vault core, or read from a file previously written by
`vault_export_credential` (raw or json format).

Usage:
  python -B scripts/model_call.py --account dsh --service magpie \
      --prompt "Say hi"                       # in-process consume
  python -B scripts/model_call.py --key-file magpie-dsh.key \
      --base-url https://model-gateway.example.com/v1 --prompt "Say hi"
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src")]

DEFAULT_BASE = None
# Per-service defaults so callers only need --service + --account.
SERVICE_BASE_URLS = {
    "deepseek": "https://api.deepseek.com/v1",
    "deepseek-api": "https://api.deepseek.com/v1",
}
SERVICE_MODELS = {
    "deepseek": "deepseek-chat",
    "deepseek-api": "deepseek-chat",
    "magpie": "group/auto-mid",
}


def default_base(service: str) -> str:
    value = os.environ.get("VAULT_MODEL_BASE_URL") or SERVICE_BASE_URLS.get(service)
    if not value:
        raise SystemExit("Specify --base-url for this service; no private gateway address is bundled.")
    return value


def default_model(service: str) -> str:
    return SERVICE_MODELS.get(service, "gpt-4o-mini")


def key_from_core(data_dir: str, port: int, service: str, account: str, operation: str) -> str:
    from agent_vault.ipc import CoreClient
    client = CoreClient(data_dir, port)
    listing = client.call_tool("vault_list", {}, {"owner_id": "local",
        "principal_id": "agent:model-call", "client_id": "execution"})
    matches = [row for row in listing.get("connections", [])
               if row.get("service_id") == service and row.get("account_alias") == account]
    if not matches:
        raise SystemExit(f"No stored credential for {service}/{account}.")
    connection_id = matches[0]["connection_id"]
    scope = client.command("consume", {"connection_id": connection_id, "scope_only": True})
    allowed = scope.get("allowed_operations") or []
    chosen = operation or next((op for op in ("chat", "completion", "read") if op in allowed), None)
    if not chosen:
        raise SystemExit(f"Credential permits no usable operation: {allowed}.")
    response = client.command("consume", {"connection_id": connection_id, "operation": chosen})
    secret = response.get("secret")
    if not isinstance(secret, str) or not secret:
        raise SystemExit("The vault did not return a usable secret.")
    return secret


def key_from_file(path: str) -> str:
    """Read a key from an exported file; raw or json format both work."""
    value = Path(path).read_text(encoding="utf-8")
    if value.lstrip().startswith("{"):
        envelope = json.loads(value)
        secret = envelope.get("secret")
        if not isinstance(secret, str) or not secret:
            raise SystemExit("The json envelope carries no secret field.")
        return secret
    return value.strip()


def call_model(base_url: str, key: str, model: str, prompt: str) -> dict:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}],
                         "stream": False}).encode(),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
        method="POST")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=60) as response:
            body = response.read(262144)
            value = json.loads(body)
            # Defense in depth: a compliant 200 must not echo the key either.
            if isinstance(value, dict) and key in json.dumps(value):
                raise SystemExit("Model call failed (HTTP 200): response contained the key; discarded.")
            return value
    except urllib.error.HTTPError as error:
        with error:
            error.read(2048)
        # Never print the upstream body: providers may echo submitted secrets.
        raise SystemExit(f"Model call failed (HTTP {error.code}); the request was not retried.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Model call with vault-backed credentials.")
    parser.add_argument("--key-file", help="read the key from an exported file instead of the core")
    parser.add_argument("--service", default="deepseek")
    parser.add_argument("--account", default="main")
    parser.add_argument("--operation", default=None, help="allowed operation; auto-selected")
    parser.add_argument("--base-url", default=None,
                        help="defaults to the service's known endpoint")
    parser.add_argument("--model", default=None, help="defaults to the service's known model")
    parser.add_argument("--prompt", default="Reply with the single word: pong")
    parser.add_argument("--data-dir", default=os.environ.get("AGENT_VAULT_DATA_DIR",
                                                             os.path.expanduser("~/.agent-vault")))
    parser.add_argument("--port", type=int, default=int(os.environ.get("AGENT_VAULT_BROKER_PORT", "43122")))
    args = parser.parse_args()
    base_url = args.base_url or default_base(args.service)
    model = args.model or default_model(args.service)
    if args.key_file:
        key = key_from_file(args.key_file)
    else:
        key = key_from_core(args.data_dir, args.port, args.service, args.account, args.operation)
    payload = call_model(base_url, key, model, args.prompt)
    choices = payload.get("choices") or [{}]
    message = choices[0].get("message") or {}
    print(json.dumps({"reply": message.get("content", ""), "model": payload.get("model"),
                      "base_url": base_url,
                      "total_tokens": (payload.get("usage") or {}).get("total_tokens")},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
