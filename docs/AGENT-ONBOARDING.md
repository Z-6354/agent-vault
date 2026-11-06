# Agent Vault 安装与 Agent 接入指南

[中文首页](../README.md) · [English](../README_EN.md)

本指南面向普通用户和支持 stdio MCP 的 Agent 宿主。基本流程是：人在通用浏览器输入凭据，核心写入数据库，Agent 查询元数据并按用户授权导出文件。无需 DSH、Hermes、共享 router 或 MCP SDK。

## 1. 安装与首次打开

需要 Python 3.12+、Git。主包运行依赖仅 `cryptography>=42`，`pip install .` 自动安装；不用先跑测试。

Windows PowerShell：

```powershell
git clone https://github.com/Z-6354/agent-vault.git
cd agent-vault
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m agent_vault open
```

`py -3` 指向 3.12+ 时也可替代 `py -3.12`。Linux：

```bash
git clone https://github.com/Z-6354/agent-vault.git
cd agent-vault
python3 --version
python3 -m venv .venv
./.venv/bin/python -m pip install .
./.venv/bin/python -m agent_vault open
```

检查 Linux 的 `python3` 为 3.12+。上述发布布局假定仓库根目录含 `pyproject.toml`；源码若嵌套在 `vault-core`，先进入它再创建虚拟环境。后续示例均从该包目录执行。

`open` 自动后台启动核心并打开浏览器。浏览器启动失败时，可手动打开默认地址 `http://127.0.0.1:43122/`；配置了端口时用对应端口。MCP 的 `vault_status` 也返回准确的 `card_url`。

首次在页面选择：

- **本地**：确认创建加密数据库，设置至少 12 位主口令；已有数据库则解锁。选择本身不创建数据库，损坏或非空目录不会自动覆盖。
- **远程**：填写你自己的兼容 HTTPS 服务，例如 `https://example.com`，探活后使用已有账户登录。仅当服务实际公开兼容初始化接口时才能在页面创建，否则交给服务管理员初始化。

浏览器、终端与 MCP 访问同一核心。默认核心端口为 43122，默认数据目录为当前用户的 `~/.agent-vault`。登录页面默认“记住此设备”，受平台保护的登录材料用于恢复；改密、记忆损坏或服务器拒绝时仍需重新登录。关闭网页不退出，退出并忘记设备才清除记忆。不记住设备时本次认证最多一小时，重启核心需重新认证。

## 2. 注册本地 MCP

安装后有两个等价入口：虚拟环境里的 `agent-vault-mcp` console entry，或虚拟环境 Python 加 `-m agent_vault.mcp_server`。所有宿主配置里的 command 都使用**绝对路径**；不能依赖宿主自动激活虚拟环境。安装主包后无需再设置 `PYTHONPATH`。

以下 `/absolute/path/...`、`C:/path/to/...` 均为示例占位路径，替换为实际安装位置，不要照抄。Windows JSON/TOML 可用正斜杠避免反斜杠转义。

### Codex：TOML

在 Codex 用户配置 `~/.codex/config.toml` 中合并以下配置，保留其他现有配置：

```toml
[mcp_servers.vault]
command = "/absolute/path/agent-vault/.venv/bin/python"
args = ["-m", "agent_vault.mcp_server"]

[mcp_servers.vault.env]
AGENT_VAULT_AGENT_ID = "codex"
```

Windows 改为：

```toml
[mcp_servers.vault]
command = "C:/path/to/agent-vault/.venv/Scripts/python.exe"
args = ["-m", "agent_vault.mcp_server"]

[mcp_servers.vault.env]
AGENT_VAULT_AGENT_ID = "codex"
```

也可把 command 改为 console entry 绝对路径（Linux `.venv/bin/agent-vault-mcp`，Windows `.venv/Scripts/agent-vault-mcp.exe`），并删除 args。重新加载 MCP 或启动新会话，然后让 Agent 调用 `vault_status`。

### Claude Code：CLI

Linux shell：

```bash
claude mcp add --transport stdio --scope user \
  --env AGENT_VAULT_AGENT_ID=claude-code \
  vault -- /absolute/path/agent-vault/.venv/bin/python -m agent_vault.mcp_server
claude mcp list
```

Windows PowerShell：

```powershell
claude mcp add --transport stdio --scope user --env AGENT_VAULT_AGENT_ID=claude-code vault -- "C:/path/to/agent-vault/.venv/Scripts/python.exe" -m agent_vault.mcp_server
claude mcp list
```

按当前 Claude Code 版本的 `claude mcp add --help` 核对宿主参数。随后重连 MCP 或重启会话。密钥或主口令不要放在 `--env` 或命令行里。

### 其他宿主：通用 MCP JSON

将条目合并到宿主支持的 MCP 配置中。常见包装形式是 `mcpServers`；具体配置位置及包装键以宿主官方文档为准。

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

Windows 将 command 替换为 `C:/path/to/agent-vault/.venv/Scripts/python.exe`。该配置启动的是本地 stdio MCP 进程；不是远程 HTTP MCP 地址。

### 可选：DSH / Hermes 共享 router

如果你另外安装了共享 MCP router，并让 DSH/Hermes 实际通过它加载 MCP，才在该 router 的注册表和 profile allowlist 中添加 vault。共享注册表、allowlist、profile、启用开关属于该 router 的约定，**不是每个 DSH/Hermes 或其他 MCP 宿主都自带的能力**。依其安装文档配置，再重启实际宿主；没有 router 时直接使用宿主原生 stdio MCP 配置即可。

### 环境变量

| 变量 | 默认 / 用途 |
|---|---|
| `AGENT_VAULT_AGENT_ID` | 默认 `default`；推荐每个宿主明确设置，用于归属与审计，非强身份认证 |
| `AGENT_VAULT_DATA_DIR` | 默认当前用户 `~/.agent-vault`；本地数据库目录，另有相邻 `.connector` 状态目录 |
| `AGENT_VAULT_BROKER_PORT` | 默认 `43122`；同一核心的浏览器、CLI、MCP 应一致 |
| `AGENT_VAULT_SERVER_URL` | 默认省略；首次可选远程 HTTPS 地址，例如 `https://example.com` |

省略服务地址时用户自行选择 local/remote，不会默认为私人服务器。已成功确认并保存的目标优先于环境默认值。后台核心已经启动后，修改宿主环境不保证改变该核心的现有配置；目标切换优先使用页面或 `vault_select_target`。不同数据目录需要不同端口，不能让同一端口复用不匹配的核心。

## 3. 录入、查询和文件交付

先调用 `vault_status {}`，人在浏览器打开 `card_url`，确认目标后登录。密码和秘密正文只输入浏览器或可信的无回显终端，不能写入聊天或 MCP 参数。

发起录入示例：

```json
{
  "service": "example.com",
  "account": "work",
  "credential_type": "api_key",
  "allowed_operations": ["chat"]
}
```

将上面参数交给 `vault_begin_enrollment`，人打开返回的 `card_url` 完成输入，再由同一 Agent 调用 `vault_result {"request_id":"<返回的 request_id>"}`。请求约 10 分钟有效；成功状态为 `captured`，附 `ref`。`vault_decline` 可拒绝请求。

`service` 和 `account` 为 1–100 位标识，首位字母或数字，后续允许字母、数字、点、下划线、连字符。`account` 对应 `account_alias`，是别名，不一定是真实登录用户名。类型可为 `password`、`api_key`、`oauth`、`external_reference`；类型标签不表示已实现 OAuth 授权或任意网站自动登录。

`allowed_operations` 是可见 scope 元数据，可选 `chat`、`completion`、`embed`、`read`、`login`、`fill`，不得重复，省略或空列表表示仅存储。授权 scope 不代表任意服务的受控执行器已经实现。

通过 `vault_find {"service_id":"example.com"}` 或 `vault_list {}` 获取 `connection_id`、服务、别名、类型、允许操作。**用户授权后**调用 `vault_export_credential`：

```json
{
  "connection_id": "<查询返回的 connection_id>",
  "operation": "chat",
  "filename": "example-key.txt",
  "format": "raw"
}
```

- `operation` 必须在该记录允许的操作中，scope 检查不会打印 secret。
- `filename` 为普通文件名，最长 128 字符，不含路径分隔符，不以点开头；不要把秘密放进文件名。
- `destination` 可省略，默认写入数据目录相邻 `.connector/exports`；指定时是受权限保护的本地绝对目录，不支持 UNC 网络目录，现有宽权限目录会被拒绝。
- `format` 默认 `raw`，直接写秘密正文；`json` 写 `{service, account, secret}`，其中 `account` 仍是别名，消费程序不可自动当作真实用户名。
- 工具返回 `path`、`bytes`、`format`、`service_id`、`account_alias` 等，不含 secret。给目标程序传路径即可，避免 `cat`、`Get-Content`、日志或聊天回显。相同目录同名文件会替换，使用明确的文件名。

**导出时生成的是本地明文文件。** 用户已接受有文件系统权限的 Agent 可以主动读取文件、使秘密进入模型上下文的风险。文件权限限制其他用户，不阻止当前用户下的模型工具读取。用完删除文件，不提交到 Git，不同步到共享目录。MCP 结果不含 secret 与模型之后能否读文件是两个不同边界。

## 4. 工具参考与执行能力

当前 schema 共 14 个工具，名称并非都以 `vault_` 开头：

| 工具 | 必需参数 / 用途 |
|---|---|
| `vault_status` | 无；状态和浏览器链接 |
| `vault_select_target` | `mode`（`local` / `remote`）；远程另需 `server_url` |
| `vault_list` | 无；凭据元数据 |
| `vault_find` | `service_id` |
| `vault_begin_enrollment` | `service`、`account`；可选 `prompt`、`credential_type`、`allowed_operations` |
| `vault_result` / `vault_decline` | `request_id` |
| `vault_export_credential` | `connection_id`、`operation`、`filename`；可选 `destination`、`format` |
| `list_connections` | 无；连接元数据 |
| `get_connection_status` | `connection_id` |
| `list_operations` | 无；实际注册的受控操作 |
| `prepare_request` | `operation_name` |
| `execute_operation` | `request_id`、`connection_id`、`operation_id`、`expected_record_version` |
| `get_operation_status` | `request_id`、`operation_id` |

工具 schema 禁止额外字段。请求 ID 为 32 字符，连接 ID 为 36 字符，使用工具真实返回值。受控执行仅限注册操作，当前通用注册表主要提供合成 mock 验证，不能声称任意网站或模型 API 开箱即用。远程兼容契约不暴露通用 MCP 受控执行；远程 `list_operations` 返回空列表。文件交付是独立于这些执行器的主要用户路径。

## 5. 远程 API、手机与云端宿主

远程模式是客户端适配器，**不包含通用远程数据库 server 的生产托管方案**。远端需提供兼容 Agent Vault Service v1，使用 HTTPS，禁止自动重定向；不能只填任意数据库或密码管理器地址。

兼容服务需在 `/openapi.json` 公布基础路径 `/api/v1/auth/login`、`/api/v1/auth/status`、`/api/v1/credentials`；完整使用还需凭据列表、解析与取用接口：

| 操作 | 接口与关键约定 |
|---|---|
| 登录 | `POST /api/v1/auth/login`，`{username,password}` → `{token}`；随后 Bearer token 校验 `GET /api/v1/auth/status` |
| 查询 | `GET /api/v1/credentials/list` → 元数据数组，包含连接 ID、服务、别名、类型、允许操作 |
| 保存 | `POST /api/v1/credentials`，含 `service_id`、`account_alias`、`secret`、`credential_type`、`allowed_operations` → `status=saved` 与 UUID `connection_id` |
| 权限解析 | `POST /api/v1/credentials/resolve`，`{mode:"exact",connection_id}` → `candidate` 或 `resolved`，含 `allowed_operations` |
| 文件导出所需取用 | `POST /api/v1/credentials/consume`，`{connection_id,operation,caller}` → `status=granted` 与 secret；仅核心内部接收正文并写文件 |
| 可选初始化 | 公布 `GET /api/v1/setup/status`；未初始化且 `POST /api/v1/setup` schema 明确只要求 `username`、`password` 时才提供创建 |

只有 OpenAPI 基础探活成功不代表完整读写/导出全部兼容，需逐项验证。服务的加密、用户管理、权限与审计由远端负责。测试 mock 不等于生产远程服务。

本地浏览器服务仅监听 `127.0.0.1`，不是公开 Web 服务。手机访问自身的 `localhost` 无法连接电脑；移动布局适配不提供安全跨设备网络通道。远程 SSH 机器上可先启动核心，再建立隧道：

```bash
ssh -L 43122:127.0.0.1:43122 user@example.com
```

在本地浏览器打开 `http://127.0.0.1:43122/`。端口冲突时调整本地转发端口；核心有 Host/Origin 校验，必要时保持同端口转发。不要为方便把服务直接暴露到公网。

云托管产品只有在官方明确支持远程 MCP 或安全输入，且能把操作交付到你控制的后端时才可评估。此包仅提供 stdio MCP，不提供远程 MCP 网关，也不能保证厂商 App 的连接器集成。没有可用的官方能力时，用浏览器/TTY 人工录入，再交给受控的本地程序；厂商侧如何持有或使用凭据取决于其官方方案。

## 6. 无浏览器时的终端兜底

必须在可信交互终端执行，秘密通过无回显输入读取；无安全终端时会拒绝操作并提示使用浏览器。不能在聊天或命令参数中传主口令。

Linux（Windows 换成 `.\.venv\Scripts\python.exe`）：

```bash
# 创建本地库；已存在则 connect --local 后 login
./.venv/bin/python -m agent_vault init

# 切换到兼容远程服务，随后登录；login 没有 --server-url 参数
./.venv/bin/python -m agent_vault connect --server-url https://example.com
./.venv/bin/python -m agent_vault login --username user

# 已有本地库
./.venv/bin/python -m agent_vault connect --local
./.venv/bin/python -m agent_vault login

# 完成 Agent 发起的录入请求（替换 request-id）
./.venv/bin/python -m agent_vault enroll request-id
./.venv/bin/python -m agent_vault status
./.venv/bin/python -m agent_vault logout
```

远程未认证时 `enroll` 可加 `--username user`。`login`、`init`、`enroll` 可加 `--no-remember`。服务切换先探活、后认证成功才替换原连接；旧表单绑定选择 ID，失效时刷新并核对目标，不要重放旧密码表单。

## 7. 故障与边界

| 现象 / 错误 | 处理 |
|---|---|
| 模块找不到 | 确认用安装该包的虚拟环境绝对解释器，重新执行其 `-m pip install .` |
| 宿主没有工具 | 检查宿主 stdio 配置与绝对 command，重连 MCP；router 用户再核对其 allowlist |
| `broker_port_in_use_or_old_version` / `core_unavailable_or_mismatched` | 核对端口、数据目录和版本；有意停止旧核心后再启动，勿复用陌生进程 |
| `login_required` / `session_expired` / `remembered_login_rejected` | 打开 card_url，核对目标并重新登录 |
| `operation_denied` | 核对该记录 `allowed_operations`，不要绕过 scope |
| `export_target_unavailable` | 使用默认导出位置或受保护的本地目录，核对权限与文件名 |
| `dns_failed` / `connection_timeout` / `connection_refused` | 检查地址、服务、实际端口和网络；客户端无法单独确认是哪层阻挡 |
| `tls_failed` / `vault_service_not_verified` | 核对 HTTPS 证书、路径前缀与服务契约，不关闭证书验证 |
| `remote_creation_unsupported` | 服务管理员先初始化 |
| `save_unconfirmed` | 先查询是否已保存，再决定重试，避免重复写入 |

平台保护无法防御同用户高权限进程和调试器。元数据、服务名、别名、scope、文件路径可对 Agent 可见；不要往这些字段塞秘密。`AGENT_VAULT_AGENT_ID` 是审计标签，不是操作系统级身份认证。

## 开发验证

普通使用不需要以下步骤。本机 Windows 与 Ubuntu/WSL 测试、真实 Linux 无回显终端及两端的干净 wheel 安装已通过；其他平台/版本组合以对应提交的 CI 实测为准。源码测试需让 `src` 和 `tests` 都在模块搜索路径中，不承诺固定用例数：

```powershell
# Windows PowerShell，包目录内
$env:PYTHONPATH="$PWD/src;$PWD/tests"
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

```bash
# Linux，包目录内
PYTHONPATH=src:tests ./.venv/bin/python -B -m unittest discover -s tests -v
```

测试使用合成数据及独立测试目录；浏览器验收等附加脚本的依赖和可用性需单独核对，不是使用门槛。
