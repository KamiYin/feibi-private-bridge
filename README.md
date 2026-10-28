# 菲比 · 本人微信文字桥接

把本人微信私聊中的文字交给既有的菲比 / dot 会话处理，再把回复送回同一个微信账号。桥接负责接收、事件通知、读取和发送；回复由原会话生成。

**2026-10-28 阶段成果：本人文字真实往返通过，并由本人在手机确认收到。** 这是 Windows x64 有限时长试用的源码与脱敏过程记录。24 小时稳定运行、图片和文件收发尚未验收。

## 本次发布包含什么

- Node.js 桥接、Windows 启动器、已有离线回归测试与隧道同源保护补丁。
- 架构、部署步骤、完整阶段时间线、问题与修复、真人验收和待办。
- 必需的二维码渲染源码、协议参考片段及相应来源、许可证。

不附带运行二进制、已登录会话、密钥、部署地址、真实回调、日志或私人聊天。源码可用于阅读和离线验证；完整在线启动还需自行准备经核验的隧道运行时和自己的服务权限，见[安装部署](docs/DEPLOYMENT.md)。

## 快速开始：离线检查

已安装 Node.js 24 后，在仓库根目录运行：

```powershell
node --version
npm test
npm run preflight
```

不需要 `npm install`。测试使用合成身份和内存网络替身；Windows 专属检查使用隔离临时目录。公开仓库不含运行时 EXE，因此预检应报告 `REVIEWED_BINARY_MISSING`，且 `launched=false`、`credential_read=false`。这不是在线连接成功。

## 阅读顺序

| 文档 | 内容 |
| --- | --- |
| [架构](docs/ARCHITECTURE.md) | 组件、消息流程、状态与权限边界 |
| [安装部署](docs/DEPLOYMENT.md) | 环境、运行时构建、配置、扫码与日常控制 |
| [过程时间线](docs/TIMELINE.md) | 从交接包到真人收发的阶段演进 |
| [问题、根因与修复](docs/TROUBLESHOOTING.md) | 已查明问题、证据和仍未知的原因 |
| [验收与进度](docs/VALIDATION.md) | 真人事实、离线证据、未完成项 |
| [公开发布说明](docs/PUBLICATION.md) | 脱敏范围、版本差异、更新约定 |
| [来源与许可](THIRD_PARTY_NOTICES.md) | 原项目参考、供应链与许可边界 |

## 源码导览

```text
src/                         通用认证、签名和状态结构
synthetic-pilot/              被正式桥接复用的协议与代理回调组件
weixin-candidate/            微信协议、本人文字中继、MCP 服务与测试
  reference/                 官方协议参考、二维码渲染器及许可
windows-pilot/               PowerShell 启动器、supervisor、代理验证
  origin-guard.patch         OpenAI tunnel-client 同源与禁重定向补丁
docs/                        中文阶段记录
```

## 当前能力

本人私聊纯文字、独立扫码确认、MCP 事件通知、同一来信上下文回复、会话内去重、固定错误码诊断、独立控制台、硬截止、可选 Windows DPAPI 隧道密钥存储。微信登录令牌、消息和去重状态仍在内存中；进程重启后需重新扫码。

公开参考：[WeChat Dot Bridge](https://github.com/cd233ljx/wechat-dot-bridge)、[weixin-bot-mcp 部署验收](https://github.com/izhx/weixin-bot-mcp/blob/main/docs/DEPLOYMENT_VALIDATION.md)。这些项目的功能和验收不等于本仓库的功能和验收。

## 更新方式与仓库权限

本次是第一份完整阶段记录。下一次有阶段进展时，在时间线末尾新增一节，并同步更新验收状态；保留早期记录对应的版本和事实。

仓库按公开可读方式发布，不主动添加外部协作者或写权限。公开仓库仍可被浏览、下载和 fork；他人提交建议或自己的副本，不会直接改动本仓库主分支。项目未擅自附加整体开源许可证，第三方文件依各自许可证保留，详见来源说明。
