"""Validate an installed package from outside its source tree.
No PYTHONPATH injection, real credentials, external APIs or user data.
"""
import http.cookiejar
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.request

import agent_vault
from agent_vault.broker import Broker


def main():
    root = Path(tempfile.mkdtemp(prefix="agent-vault-installed-"))
    directory = root / "data"
    broker = Broker(str(directory), 0)
    server = broker.build_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{broker.port}"
    jar = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
    env = {key: value for key, value in os.environ.items() if key not in
           ("PYTHONPATH", "AGENT_VAULT_SERVER_URL")}
    env.update(AGENT_VAULT_DATA_DIR=str(directory), AGENT_VAULT_BROKER_PORT=str(broker.port),
               AGENT_VAULT_AGENT_ID="install-check")
    csrf = ""
    def post(path, data):
        request = urllib.request.Request(base + path, data=json.dumps(data).encode(),
            headers={"Content-Type":"application/json", "Origin":base, "X-Vault-CSRF":csrf})
        with browser.open(request, timeout=10) as response:
            return json.loads(response.read())
    def call(name, args):
        messages = [{"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}},
                    {"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":name,"arguments":args}}]
        child = subprocess.run([sys.executable,"-B","-m","agent_vault.mcp_server"],
            input="\n".join(json.dumps(message) for message in messages)+"\n",
            capture_output=True, text=True, cwd=root, env=env, timeout=25)
        if child.returncode:
            raise RuntimeError("installed MCP entry failed")
        response = json.loads(child.stdout.splitlines()[-1])["result"]
        if response.get("isError"):
            raise RuntimeError("installed MCP operation failed")
        return json.loads(response["content"][0]["text"])
    password = "synthetic-install-passphrase"
    secret = "synthetic-install-key"
    try:
        with browser.open(base + "/", timeout=5) as response:
            page = response.read().decode()
        csrf = re.search(r'name="vault-csrf" content="([^\"]+)"', page).group(1)
        assert "remember-device" in page
        selection = post("/api/select", {"mode":"local"})
        post("/api/create", {"selection_id":selection["selection_id"], "passphrase":password,
                            "confirm":password, "remember_device":False})
        assert call("vault_status", {})["connected"]
        request = call("vault_begin_enrollment", {"service":"install-check", "account":"main",
            "credential_type":"api_key", "allowed_operations":["read"]})
        post("/api/submit", {"request_id":request["request_id"], "secret":secret})
        result = call("vault_result", {"request_id":request["request_id"]})
        assert result["status"] == "captured"
        row = call("vault_list", {})["connections"][0]
        exported = call("vault_export_credential", {"connection_id":row["connection_id"],
            "operation":"read", "filename":"installed.key"})
        assert Path(exported["path"]).read_text() == secret
        assert secret not in json.dumps(result) + json.dumps(row) + json.dumps(exported)
        print(json.dumps({"installed_package":str(Path(agent_vault.__file__).resolve()),
            "browser_create":"ok", "stdio_shared_session":"ok", "save_and_export":"ok",
            "secret_absent_from_results":True}))
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        shutil.rmtree(root)


if __name__ == "__main__":
    raise SystemExit(main())
