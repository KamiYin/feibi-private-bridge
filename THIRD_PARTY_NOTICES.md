# 来源、依赖与许可

本仓库整理本地桥接实现及修复。没有给整个项目擅自选择 MIT、Apache 或其他整体许可证；可见源码不等于新增一份未经确认的授权。下列第三方源码和补丁相关权利以原许可为准。

| 来源 | 本仓库用途 | 保留材料 |
| --- | --- | --- |
| [OpenAI tunnel-client](https://github.com/openai/tunnel-client) v0.0.18，提交 `274a5588414819f063d27100a4fb1096aae3830f` | 外部隧道运行时与同源 / 禁重定向补丁；不附 EXE | `windows-pilot/origin-guard.patch`、构建记录、`licenses/openai-tunnel-client-LICENSE`、`licenses/openai-tunnel-client-NOTICE` |
| [Tencent openclaw-weixin](https://github.com/Tencent/openclaw-weixin)，npm `@tencent-weixin/openclaw-weixin` 2.1.10 | 官方二维码与 API 源码参考片段 | `weixin-candidate/reference/LICENSE`、`legacy-2.1.10/PROVENANCE.json` 和两个参考源文件；原许可为 MIT |
| [qrcode-terminal](https://github.com/gtanner/qrcode-terminal) 0.12.0 | 仅 QRCode 算法源码，供本机 PNG 编码器调用 | `weixin-candidate/reference/qr-renderer/LICENSE`、`PROVENANCE.json`、`vendor/QRCode/`；包许可 Apache-2.0，内含 Kazuhiko Arase QRCode 的 MIT 归属 |
| [WeChat Dot Bridge](https://github.com/cd233ljx/wechat-dot-bridge) | 公开架构 / 方案参考 | 链接归属；不把其 Linux、多模态或持久化功能写成本项目已完成 |
| [weixin-bot-mcp 部署验收](https://github.com/izhx/weixin-bot-mcp/blob/main/docs/DEPLOYMENT_VALIDATION.md) | 公开部署、验收分层和脱敏记录参考 | 链接归属；未复制其部署数据或将其测试总数归入本项目 |

本地材料不足以确认整个桥接所有片段的最初作者及完整衍生链，本仓库不作“全部原创”或“完整复刻某上游”的声明。通用代码保留既有命名；如后续补足来源，应追加明确记录和必要归属。

Go 的依赖版本来自原构建 `binary-build-info.txt`，不是本次重新解析出的最新版本。公开包未分发 Go 二进制及其打包依赖。自行构建或再分发运行时，应保留上游和所用依赖要求的许可证 / NOTICE。JavaScript 运行部分只使用 Node 内置模块及上述已保留 QRCode 源码。

`origin-guard.patch` 明确标记本地修改的上游文件：`pkg/controlplane/internal/roundtripper.go`、`tunnel_service_client.go` 及相关测试。它增加请求来源核验、拒绝重定向及相应测试；其来源 Apache-2.0 许可与 NOTICE 一并保留。
