# Agent Vault

在浏览器里输入凭据，保存到加密数据库，再通过 MCP 把授权的凭据交付为本地文件，供你控制的程序使用。Agent Vault 不绑定某个 Agent 宿主；支持 stdio MCP 的本地宿主可直接接入。

[English](README_EN.md) · [完整安装与宿主配置](docs/AGENT-ONBOARDING.md)

```text
人 → 浏览器 / 无回显终端 → 本机连接核心 → 本地加密数据库 / 兼容远程 API
Agent → stdio MCP        → 同一连接核心 → 元数据、录入链接、授权导出的文件路径
```

MCP 的录入参数和工具返回不包含密钥正文。**导出会生成本地明文文件**：有文件系统权限的 Agent 可以主动读取它，进而把内容带入模型上下文。选择导出即接受这项风险；这不是“密钥永不被模型读取”的保证。

## 安装并打开

需要 Git、Python **3.12+**。主包唯一运行时第三方依赖是 `cryptography>=42`，安装包时自动安装，**无需 MCP SDK**。普通用户不用运行测试即可使用。

Windows PowerShell：

```powershell
git clone https://github.com/Z-6354/agent-vault.git
cd agent-vault
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m agent_vault open
```

若 `py -3` 已指向 Python 3.12 或更新版本，也可用 `py -3 -m venv .venv`。

Linux：

```bash
git clone https://github.com/Z-6354/agent-vault.git
cd agent-vault
python3 --version  # 需为 3.12+
python3 -m venv .venv
./.venv/bin/python -m pip install .
./.venv/bin/python -m agent_vault open
```

以上按发布仓库根目录包含 `pyproject.toml` 的布局编写；如果拿到的源码外层还有 `vault-core`，先进入该目录再创建虚拟环境、安装。

`open` 自动启动本机后台核心并打开浏览器。首次在页面选择本地或远程：本地金库设置至少 12 位主口令；远程金库使用兼容服务的账号登录。仅选择目标不会创建数据库，创建需要人在页面确认。浏览器未自动打开时，调用 `status` 并打开本机地址（默认 `http://127.0.0.1:43122/`），或通过 MCP 的 `vault_status` 获取 `card_url`。

## 连接你的 Agent

在宿主中注册 `agent-vault-mcp`，或虚拟环境里的 Python 加参数 `-m agent_vault.mcp_server`。**command 使用安装后的绝对路径**，避免宿主的 PATH、工作目录和当前终端不同。

例如，通用 MCP JSON（示例路径为占位值，请替换为自己的虚拟环境路径）：

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

Windows 的 `command` 可用 `C:/path/to/agent-vault/.venv/Scripts/python.exe`。配置后重启或重新连接宿主 MCP。Codex TOML、Claude Code CLI、Windows/Linux 完整示例见[接入指南](docs/AGENT-ONBOARDING.md)。DSH/Hermes 的共享 router 是可选高级集成，需要另行安装；并非每个宿主自带的通用功能。

## 录入与交付

1. Agent 调用 `vault_status`，人打开 `card_url` 登录或创建金库。
2. Agent 调用 `vault_begin_enrollment`，只提供服务、账号别名、类型和允许操作；人在返回的浏览器页面输入秘密。
3. Agent 调用 `vault_result` 确认保存，再用 `vault_find` 或 `vault_list` 查询元数据。
4. 用户授权文件交付后，Agent 调用 `vault_export_credential`，指定记录、允许的操作和文件名；工具返回路径及元数据，不打印秘密。

`account` / `account_alias` 是**账号别名**，可以是便于区分凭据的标签，不一定是网站用户名。导出 JSON 的 `account` 仍是该别名；消费程序需要真实用户名时须另行核对。

`allowed_operations` 可为 `chat`、`completion`、`embed`、`read`、`login`、`fill`，省略或空列表表示仅存储，不能导出。scope 检查和文件名不会打印 secret；不要把秘密放进服务名、别名、提示或文件名。导出 `raw` 是秘密文本，`json` 是 `{service, account, secret}`。用完删除明文文件，避免加入版本控制、日志或共享目录。

## 远程与手机的边界

默认不设置 `AGENT_VAULT_SERVER_URL`，首次由用户选本地或远程。可选远程地址示例为 `https://example.com`；已确认保存的目标优先于环境默认值。

远程模式是**兼容 Agent Vault Service v1 API 的客户端适配器**，本包不包含通用远程数据库服务的生产托管、部署或账户管理方案。并非任意密码管理器或数据库 URL 都能连接；服务需实现认证、凭据读写、权限解析和授权取用接口。远端存储保护由该服务负责，具体契约见[接入指南](docs/AGENT-ONBOARDING.md)。

浏览器服务仅监听本机 loopback。手机上的 `localhost` / `127.0.0.1` 指手机自身，不能直接访问电脑页面；移动浏览器布局适配不代表已提供跨设备网络通道。SSH 场景可使用端口转发，在受控设备浏览器完成输入。

云托管 Agent 仅在厂商官方明确支持远程 MCP 或安全输入、并能把操作交付到你控制的后端时才可评估接入。本包的 MCP 是本地 stdio，不自带远程 MCP 网关；没有官方能力时使用浏览器/TTY 完成人工录入及本地程序交付，不能保证厂商集成。

## 安全与支持状态

本地凭据保存在加密 SQLite 数据库，设备登录记忆使用平台保护；关闭网页不等于退出。页面的“退出并忘记此设备”会清除登录记忆。选择不记住设备时，核心重启后需重新登录，本次认证最多一小时。

文件权限、Windows DPAPI 等是当前用户级保护，无法防御同用户高权限进程、调试器或已获文件访问权的模型。`AGENT_VAULT_AGENT_ID` 是宿主自声明的审计标识，不是强身份认证。受控执行仅限实际注册的操作，不能因允许了 `chat` 就推断任何模型服务都已集成。

本机已验证 Windows 与 Ubuntu/WSL（含真实无回显终端），并验证从构建包全新安装后的浏览器→MCP→文件交付。Windows、Linux、macOS 的 Python 3.12/3.14 组合由 [GitHub CI](https://github.com/Z-6354/agent-vault/actions) 持续验证，以对应提交的实际检查结果为准。开发测试命令见[接入指南](docs/AGENT-ONBOARDING.md#开发验证)。

## License

MIT，见 [LICENSE](LICENSE)。
