"""Host-neutral stdio MCP transport. No Vault/database/login state lives here."""
from __future__ import annotations

import json
import os
import sys

from .errors import VaultError
from .ipc import CoreClient


def field(maximum=512, minimum=1):
    return {"type": "string", "minLength": minimum, "maxLength": maximum}


def tool(name, description, properties=None, required=None):
    properties = properties or {}
    return {"name": name, "description": description, "inputSchema": {
        "type": "object", "properties": properties,
        "required": list(properties) if required is None else required, "additionalProperties": False}}


TOOLS = [
    tool("vault_status", "Connection state and safe browser link; never secrets."),
    tool("vault_select_target", "Select local or probe a user-specified HTTPS vault server. "
         "No database is created and no old session is replaced until browser authentication succeeds.",
         {"mode": {"type": "string", "enum": ["local", "remote"]}, "server_url": field(2048)}, ["mode"]),
    tool("vault_list", "List credential metadata only."),
    tool("vault_find", "Find credential metadata by service.", {"service_id": field(100)}),
    tool("vault_begin_enrollment", "Request credential entry in the browser. Never pass secrets.",
         {"service": field(100), "account": field(100), "prompt": field(),
          "credential_type": {"type": "string", "enum": ["password", "api_key", "oauth", "external_reference"]},
          "allowed_operations": {"type": "array", "items": {"type": "string",
              "enum": ["chat", "completion", "embed", "read", "login", "fill"]}, "maxItems": 20}},
         ["service", "account"]),
    tool("vault_result", "Read enrollment state/reference only.", {"request_id": field(32, 32)}),
    tool("vault_decline", "Decline an enrollment.", {"request_id": field(32, 32)}),
    tool("list_operations", "List controlled operations supported by the selected backend."),
    tool("list_connections", "List connection metadata only."),
    tool("prepare_request", "Create a controlled operation ticket.", {"operation_name": field(100)}),
    tool("execute_operation", "Execute a registered operation inside the local core; remote legacy consume is not exposed.",
         {"request_id": field(32, 32), "connection_id": field(36, 36), "operation_id": field(100),
          "expected_record_version": {"type": "integer", "minimum": 1}}),
    tool("vault_export_credential", "Write a stored credential to a protected local file and return "
         "only the file path. The secret never appears in this result; an agent with file access "
         "can read the file afterwards. format=json writes {service, account, secret} for login-style use.",
         {"connection_id": field(36, 36), "operation": field(64),
          "filename": field(128), "destination": field(2048),
          "format": {"type": "string", "enum": ["raw", "json"]}},
         ["connection_id", "operation", "filename"]),
    tool("get_connection_status", "Get connection metadata.", {"connection_id": field(36, 36)}),
    tool("get_operation_status", "Get durable operation result.",
         {"request_id": field(32, 32), "operation_id": field(100)}),
]
_BY_NAME = {item["name"]: item["inputSchema"] for item in TOOLS}


def validate_arguments(name, arguments):
    if not isinstance(name, str) or name not in _BY_NAME or not isinstance(arguments, dict):
        raise VaultError(400, "invalid_tool_request")
    schema = _BY_NAME[name]
    if set(arguments) - set(schema["properties"]) or not set(schema["required"]).issubset(arguments):
        raise VaultError(400, "invalid_tool_request")
    for key, value in arguments.items():
        rule = schema["properties"][key]
        if rule["type"] == "string":
            if not isinstance(value, str) or not rule.get("minLength", 0) <= len(value) <= rule.get("maxLength", 2048):
                raise VaultError(400, "invalid_tool_request")
        elif rule["type"] == "integer":
            if type(value) is not int or value < rule.get("minimum", 0):
                raise VaultError(400, "invalid_tool_request")
        elif rule["type"] == "array":
            if (not isinstance(value, list) or len(value) > rule.get("maxItems", 20)
                    or not all(isinstance(item, str) and item in rule["items"]["enum"] for item in value)):
                raise VaultError(400, "invalid_tool_request")
        if "enum" in rule and value not in rule["enum"]:
            raise VaultError(400, "invalid_tool_request")


class McpServer:
    def __init__(self, client: CoreClient, *, agent_id=None):
        self.client = client
        self.agent_id = agent_id or os.environ.get("AGENT_VAULT_AGENT_ID", "default")

    def call_tool(self, name, arguments):
        try:
            validate_arguments(name, arguments)
            auth = {"owner_id": "local", "principal_id": "agent:" + self.agent_id, "client_id": "execution"}
            value = self.client.call_tool(name, arguments, auth)
            # Link generation belongs to this transport; it always points to
            # the same authenticated local core as the tool request.
            if name in ("vault_status", "vault_select_target"):
                value["card_url"] = self.client.url + "/"
                if not value.get("connected"):
                    value["next_action"] = "Open card_url to select a target, log in or create the vault. Never enter secrets in chat."
            elif name == "vault_begin_enrollment":
                value["card_url"] = self.client.url + "/connect/" + value["request_id"]
                value["next_action"] = "Complete credential entry in the browser; then call vault_result."
            return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}]}
        except VaultError as error:
            return {"isError": True, "content": [{"type": "text", "text": json.dumps({
                "error": error.code, "card_url": self.client.url + "/"})}]}

    def handle(self, message):
        try:
            return self._dispatch(message)
        except VaultError as error:
            identifier = message.get("id") if isinstance(message, dict) else None
            return {"jsonrpc": "2.0", "id": identifier, "result": {"isError": True,
                "content": [{"type": "text", "text": json.dumps({"error": error.code})}]}}
        except Exception:
            # Fixed code only: unexpected exceptions may carry secret material
            # in their text, and the stdio loop must survive them.
            identifier = message.get("id") if isinstance(message, dict) else None
            return {"jsonrpc": "2.0", "id": identifier, "result": {"isError": True,
                "content": [{"type": "text", "text": json.dumps({"error": "internal_error"})}]}}

    def _dispatch(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or "id" not in message:
            return None
        identifier = message["id"]
        method, params = message.get("method"), message.get("params", {})
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32602, "message": "Invalid params"}}
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "agent-vault", "version": "2.0.0"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            result = self.call_tool(params.get("name"), params.get("arguments", {}))
        else:
            return {"jsonrpc": "2.0", "id": identifier, "error": {"code": -32601, "message": "Method not found"}}
        return {"jsonrpc": "2.0", "id": identifier, "result": result}


def main():
    from .broker import ensure_running
    directory = os.environ.get("AGENT_VAULT_DATA_DIR", os.path.expanduser("~/.agent-vault"))
    try:
        port = int(os.environ.get("AGENT_VAULT_BROKER_PORT", "43122"))
        ensure_running(directory, port)
        server = McpServer(CoreClient(directory, port))
    except (VaultError, OSError, ValueError):
        sys.stderr.write("Vault core unavailable or incompatible. Check the configured core port and version.\n")
        return 1
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
    for line in sys.stdin:
        try:
            response = server.handle(json.loads(line))
        except ValueError:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        if response is not None:
            print(json.dumps(response, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
