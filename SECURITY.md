# Security / 安全说明

Agent Vault 将输入、存储和输出分离：MCP 的正常返回值不包含凭据正文；用户在独立安全页面或可信无回显终端输入；按授权可将密钥交付为本机文件。

## Trust boundary / 信任边界

- 导出文件是明文，具有文件系统权限的 Agent 可主动读取它。不要将“不在 MCP 返回值里回显”理解为隔离同用户下的所有工具。
- Windows 设备记忆使用当前用户 DPAPI；POSIX 使用 0700 目录、0600 私钥与 AES-GCM。POSIX 下若攻击者获取整盘，需依赖额外的磁盘加密。
- 同用户的高权限进程、恶意浏览器扩展、调试器和管理员不在本产品隔离范围内。宿主声明的 Agent ID 不是强身份认证。
- 本地核心仅监听 loopback；不应直接将此端口转发到公网。远程金库 API 需独立实现 HTTPS、账户控制、加密存储与运维。
- 密钥文件、数据库、设备记忆和日志不应提交到 Git。若曾将实际密钥发到聊天、日志或公开仓库，应按对应提供方的流程撤销/轮换，而非仅删除消息。

## Report a vulnerability / 报告漏洞

请优先通过 GitHub 的 **Security → Report a vulnerability** 私下报告：
https://github.com/Z-6354/agent-vault/security/advisories/new

不要在公开 issue 中粘贴实际密码、API Key、设备记忆、数据库或完整日志。使用合成 canary 和最小复现描述；如私密报告不可用，可先提交不含敏感细节的 issue 请求联系渠道。

请包含版本、操作系统、复现步骤、预期行为与实际结果。修复验证会区分合成测试、真实宿主和生产业务，避免扩大证据结论。
