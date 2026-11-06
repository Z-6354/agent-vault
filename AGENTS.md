# Agent Vault：仓库内 Agent 指南

普通用户从 [README.md](README.md) 开始；英文入口是 [README_EN.md](README_EN.md)，详细宿主配置与接口说明见 [docs/AGENT-ONBOARDING.md](docs/AGENT-ONBOARDING.md)。

## 产品与真实入口

这是宿主无关的 Python 包：人在浏览器或可信无回显终端输入凭据，单一本机核心协调本地加密 SQLite 数据库或兼容远程 API，Agent 经 stdio MCP 查询元数据、发起录入和交付授权文件。DSH/Hermes 共享 router 是另行安装的可选集成，不是默认依赖，也不是所有 MCP 宿主的共同功能。

查证行为时先读 [pyproject.toml](pyproject.toml)、[CLI](src/agent_vault/__main__.py)、[MCP schema](src/agent_vault/mcp_server.py)、[连接核心](src/agent_vault/connection.py)、[浏览器服务](src/agent_vault/broker.py) 和 [远程适配器](src/agent_vault/remote.py)。不要为核对文档读取本机凭据、用户数据库、设备记忆或生产配置；测试使用合成数据。

- 主包 Python >=3.12，唯一第三方运行依赖为 cryptography；无需 MCP SDK。
- 推荐 clone → `python -m venv .venv` → 虚拟环境 `python -m pip install .` → `python -m agent_vault open`。Windows 创建环境用 `py -3.12` 或指向 3.12+ 的 `py -3`；Linux 用 3.12+ 的 `python3`。
- MCP 入口是 `agent-vault-mcp`，或虚拟环境 Python 的 `-m agent_vault.mcp_server`。宿主 command 用绝对路径；安装后无需 PYTHONPATH。
- `login --server-url` 不存在：先 `connect --server-url https://example.com`，再 `login --username user`。秘密正文只能经可信交互输入。
- 当前工具名称并非全带 `vault_` 前缀，以实际 tools/list 为准，勿把固定工具数写成稳定 API 保证。

## Agent 使用约束

1. 先调用 `vault_status`，让用户打开 `card_url` 并确认目标。不要在聊天里索要主口令或 secret。
2. `vault_begin_enrollment` 只传服务、账号别名、类型、提示和允许操作。人完成浏览器/TTY 输入后用 `vault_result` 确认。
3. 使用 `vault_find` / `vault_list` 返回的 connection ID 与 scope。`account_alias` 是别名，不能推断为真实用户名；导出 JSON 的 `account` 也只是该别名。
4. 用户授权文件交付后，可调用 `vault_export_credential`；`operation` 必须在允许 scope 内，filename 只用非秘密的普通文件名。scope/filename 不打印 secret，不得将秘密编码进这些元数据。
5. 导出是本地明文文件，工具仅返回路径及元数据。用户已接受有文件系统权限的模型可主动读取该文件并将其带入上下文的风险，不能宣称“模型永远看不到密钥”。将路径交给目标程序，避免无必要的聊天/日志回显，用完删除。
6. 空 scope 表示仅存储；类型为 oauth 不代表已实现 OAuth 连接器，允许 chat 不代表任意服务已有执行器。受控执行能力以实际注册操作为准。
7. 保存不确认时先查询再决定重试；不能盲目重放含秘密的写入。切换目标必须等待新目标认证成功，旧表单失效后刷新核对。

## 部署与文档边界

- 不为 `AGENT_VAULT_SERVER_URL` 填私人默认值；省略时让用户选 local/remote，通用远程示例统一 `https://example.com`。
- 本包远程能力是兼容 API 客户端，不包含所有远程 DB server 的生产部署和托管。基础 OpenAPI 探活不证明完整读写/导出兼容。
- 浏览器核心仅监听 loopback。手机 localhost 指向手机，不能据移动布局适配承诺手机能直连电脑。需要受控网络通道，例如适当的 SSH 转发。
- 云托管产品须有官方明确的远程 MCP / 安全输入能力，并能交付到我方控制的后端，才可评估接入；无此能力则浏览器/TTY 兜底，不保证厂商集成。本包不自带远程 MCP 网关。
- 不写私人域名、实际主机路径或私人账号。示例路径明确为占位符，外部服务示例统一 example.com。
- 本机 Windows 与 Ubuntu/WSL 测试及干净安装已通过；其他平台/版本组合以对应提交的 CI 实测为准。不要求普通用户先运行开发测试。

## 开发验证

只运行与改动相符的检查。纯文档核对实际接口、示例和链接即可，无需无关业务测试。开发测试从包目录运行，src 与 tests 均需在搜索路径：

```powershell
$env:PYTHONPATH="$PWD/src;$PWD/tests"
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

```bash
PYTHONPATH=src:tests ./.venv/bin/python -B -m unittest discover -s tests -v
```

不要声称未实际执行的平台测试成功。提交、推送、发布以及修改用户的宿主配置须遵循当前任务授权。
