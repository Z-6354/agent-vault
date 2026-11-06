# Agent Vault

Enter credentials in your browser, store them in an encrypted database, and use MCP to deliver authorized credentials as local files to programs you control. Agent Vault works with local stdio MCP hosts; it does not require DSH, Hermes, a shared router, or an MCP SDK.

[中文首页](README.md) · [Detailed setup and host configuration (Chinese)](docs/AGENT-ONBOARDING.md)

```text
Human → browser / trusted terminal → local core → encrypted local DB / compatible remote API
Agent → stdio MCP                 → same core → metadata, enrollment links, exported file paths
```

MCP enrollment arguments and results do not contain secret values. **Export creates a local plaintext file.** An agent with filesystem access can read that file and bring its contents into model context. Authorizing export accepts this risk; this is not a guarantee that models can never read your credentials.

## Install and open

Requirements: Git and **Python 3.12+**. The main package has one third-party runtime dependency, `cryptography>=42`, installed automatically by pip. No MCP SDK is required. Users do not need to run tests before using the package.

Windows PowerShell:

```powershell
git clone https://github.com/Z-6354/agent-vault.git
cd agent-vault
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m agent_vault open
```

You may use `py -3` if it selects Python 3.12 or newer. Linux:

```bash
git clone https://github.com/Z-6354/agent-vault.git
cd agent-vault
python3 --version  # must be 3.12+
python3 -m venv .venv
./.venv/bin/python -m pip install .
./.venv/bin/python -m agent_vault open
```

These commands assume the release repository root contains `pyproject.toml`. If your source tree has an outer directory containing `vault-core`, enter `vault-core` before creating the virtual environment and installing.

`open` starts the local core in the background and opens the browser. If the browser does not launch, open `http://127.0.0.1:43122/` manually, or use the `card_url` returned by MCP `vault_status` for the configured port. Choose local or remote storage. Local creation requires explicit confirmation and a passphrase of at least 12 characters. Remote mode requires an existing compatible HTTPS service and its account credentials. Selecting a target alone does not create a database.

## Configure your MCP host

Use an **absolute executable path** from the virtual environment. Either run its `agent-vault-mcp` console entry or its Python with `-m agent_vault.mcp_server`. Installed packages do not need `PYTHONPATH`.

Codex: merge this into `~/.codex/config.toml`:

```toml
[mcp_servers.vault]
command = "/absolute/path/agent-vault/.venv/bin/python"
args = ["-m", "agent_vault.mcp_server"]

[mcp_servers.vault.env]
AGENT_VAULT_AGENT_ID = "codex"
```

On Windows, replace command with `C:/path/to/agent-vault/.venv/Scripts/python.exe`. All paths here are placeholders to replace with your own installation path.

Claude Code, Linux shell:

```bash
claude mcp add --transport stdio --scope user \
  --env AGENT_VAULT_AGENT_ID=claude-code \
  vault -- /absolute/path/agent-vault/.venv/bin/python -m agent_vault.mcp_server
claude mcp list
```

Windows PowerShell:

```powershell
claude mcp add --transport stdio --scope user --env AGENT_VAULT_AGENT_ID=claude-code vault -- "C:/path/to/agent-vault/.venv/Scripts/python.exe" -m agent_vault.mcp_server
claude mcp list
```

Check your installed host's `claude mcp add --help` for its current options. Reconnect MCP or start a new host session after configuration.

Generic MCP JSON (use your host's documented location and wrapper keys):

```json
{
  "mcpServers": {
    "vault": {
      "command": "/absolute/path/agent-vault/.venv/bin/python",
      "args": ["-m", "agent_vault.mcp_server"],
      "env": {"AGENT_VAULT_AGENT_ID": "my-agent"}
    }
  }
}
```

For the console entry, use the absolute `.venv/bin/agent-vault-mcp` or `.venv/Scripts/agent-vault-mcp.exe` path and omit args. DSH/Hermes shared routers are optional advanced integrations that must be installed and configured separately. Shared registries and profile allowlists are router conventions, not universal host features.

## Enter and deliver a credential

1. Call `vault_status {}` and let the user open `card_url` to authenticate.
2. Call `vault_begin_enrollment` with metadata only, for example `{"service":"example.com","account":"work","credential_type":"api_key","allowed_operations":["chat"]}`.
3. The user enters the secret in the returned browser link. Call `vault_result` with the returned request ID to confirm `captured`; enrollment expires after about ten minutes.
4. Call `vault_find {"service_id":"example.com"}` or `vault_list {}` to obtain the record's connection ID and scope.
5. Once the user authorizes file delivery, call `vault_export_credential` with that `connection_id`, an allowed `operation`, and a safe `filename`, such as `example-key.txt`.

Types: `password`, `api_key`, `oauth`, `external_reference`. A type label does not implement an OAuth flow or website integration. Service and account identifiers are 1–100 characters, start with a letter or digit, and otherwise allow letters, digits, dots, underscores and hyphens.

`account` / `account_alias` is an **alias**, not necessarily a real login username. `allowed_operations` accepts `chat`, `completion`, `embed`, `read`, `login`, `fill`; omitted or empty scope means storage only and prevents export. Scope checks and filenames do not print secret values. Never put a secret into metadata, prompts, filenames or command arguments.

Export defaults to `format: "raw"`; `format: "json"` writes `{service, account, secret}`, where account is still the alias. The result contains a local path and metadata, not the secret. An optional destination must be an absolute protected local directory; UNC paths are unsupported. Otherwise the core uses its protected export directory. A filename must not contain path separators or start with a dot; the maximum length is 128 characters. An existing file at the same target name is replaced.

Give the target program the path. Avoid printing the file into chat or logs; delete it after use and keep it out of version control and shared directories. File permissions do not stop an agent running as the same user from reading an authorized export. That filesystem risk is accepted at export time.

Controlled execution is limited to actually registered operations; the current generic registry primarily supplies a synthetic mock operation. A scope such as `chat` does not imply an arbitrary model provider has a built-in executor. Remote controlled execution is not exposed by the current compatibility contract.

## Remote, mobile and hosted agents

`AGENT_VAULT_SERVER_URL` is optional and has no private default. Omit it to choose local/remote in the browser. A remote example is `https://example.com`; a previously confirmed saved target takes precedence over an environment default.

Remote mode is a client adapter for **Agent Vault Service v1**, not a general remote database server hosting solution. The package does not supply production hosting, remote account administration, or compatibility with arbitrary password managers. A service must expose compatible OpenAPI discovery, authentication, credential storage/listing, permission resolution and authorized consume endpoints. Passing the basic probe does not prove every operation is compatible. Remote encryption, authorization and auditing remain the remote service's responsibility. See the [API contract table](docs/AGENT-ONBOARDING.md#5-远程-api手机与云端宿主).

The local browser service listens on loopback only. A phone's `localhost` or `127.0.0.1` refers to the phone, not your PC. Mobile-friendly layout does not provide a secure cross-device network channel. For an SSH machine, use a controlled tunnel such as `ssh -L 43122:127.0.0.1:43122 user@example.com`, then open the local browser URL. Do not expose the local core directly to the public internet.

A cloud-hosted product is usable only if the vendor officially supports remote MCP or secure input and can deliver the operation to a backend you control. This package supplies local stdio MCP, not a remote MCP gateway. Without an official supported route, use browser/TTY entry and local program delivery; vendor integration cannot be guaranteed.

## Terminal fallback

Use a trusted interactive terminal with hidden input. On Linux:

```bash
./.venv/bin/python -m agent_vault init
# Remote selection, then login (login has no --server-url option):
./.venv/bin/python -m agent_vault connect --server-url https://example.com
./.venv/bin/python -m agent_vault login --username user
# Existing local vault:
./.venv/bin/python -m agent_vault connect --local
./.venv/bin/python -m agent_vault login
```

On Windows use `.\.venv\Scripts\python.exe`. `enroll request-id` completes an enrollment using hidden input. `--no-remember` is available for authentication/enrollment. If secure terminal input is unavailable, use the browser; do not pass passwords as command arguments.

## Security and validation status

The local database is encrypted SQLite. Remembered login material uses platform protection. Closing the browser does not log out; use the page's logout/forget action to remove remembered authentication. Without device remembering, authentication lasts at most an hour and must be repeated after a core restart.

Protection is at the current-user boundary. Same-user privileged processes, debuggers and agents with filesystem access may read process memory or exported files. `AGENT_VAULT_AGENT_ID` is a host-declared audit label, not strong OS identity.

Local tests have passed on Windows and Ubuntu/WSL, including real no-echo terminal input and clean-wheel browser/MCP/file-delivery checks. [GitHub CI](https://github.com/Z-6354/agent-vault/actions) checks Windows, Linux and macOS with Python 3.12/3.14; use the checks for the specific commit as the support evidence. Development tests are optional for users. From the package directory:

```powershell
$env:PYTHONPATH="$PWD/src;$PWD/tests"
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

```bash
PYTHONPATH=src:tests ./.venv/bin/python -B -m unittest discover -s tests -v
```

## License

MIT. See [LICENSE](LICENSE).
