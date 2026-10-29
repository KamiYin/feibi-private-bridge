# 菲比私人微信桥接

0.3.0 源码：将已绑定本人的微信私聊接入已有 dot 会话，支持文字、普通图片与文件双向传递。桥接不调用额外模型，附件按需读取，不强制识别或摘要。

- 同一请求可多次回复；每次发送独立幂等，unknown 不自动重发。
- 可向当前绑定本人主动发送文字；使用最近真实来信提供的 contextToken，不开放收件人参数。微信是否接受过期上下文由服务端决定。
- 显式批量标记 handled，处理完成与发送结果分开；支持旧加密状态迁移。
- 混合消息保留支持的内容，不支持项给出类型元数据；普通 GIF 文件可以传，微信动态展示未通过验收。
- 图片返回 MCP image；文件返回 resource/blob。大文件可用 offset/length 分段，同一原件只下载一次。
- 媒体模式 MCP 并发 4；附件准备最多两份并行且保留顺序；连接、下载与上传结果复用。
- Windows 当前用户计划任务后台运行，DPAPI 保护密钥，原状态恢复登录与订阅。

## 使用

需要自己的官方 Tunnel、授权账号、微信绑定和 dot 插件／Events 订阅。源码不包含原部署的身份、密钥、绑定、订阅或文件；复制代码不会自动接入原作者的会话。

Windows x64、PowerShell 5.1 STA、Node.js 24+。无需 npm install。源码不带运行 EXE；构建与部署见 [DEPLOYMENT](docs/DEPLOYMENT.md)。

~~~powershell
npm test
npm run preflight
~~~

未配置二进制时预检报告 REVIEWED_BINARY_MISSING，且不会启动或读取凭据。

## 文档

- [工具语义与架构](docs/ARCHITECTURE.md)
- [部署与恢复](docs/DEPLOYMENT.md)
- [性能改动与证据](docs/PERFORMANCE.md)
- [验证记录](docs/VALIDATION.md)
- [故障处理](docs/TROUBLESHOOTING.md)
- [发布差异与排除项](docs/PUBLICATION.md)
- [第三方来源](THIRD_PARTY_NOTICES.md)
- [历史 0.2 里程碑](docs/MILESTONE_02.md)
- [历史 0.2 详细验证、性能与排障证据](docs/MILESTONE_02_EVIDENCE.md)

未引入永久固定微信身份；沿用当前绑定本人入站与出站检查。本文档不把私有原型验收等同于任意宿主都支持 fileParams。宿主需实际提供文件参数注入与二进制工具结果处理。项目尚未选择自有代码的通用开源许可证，第三方许可证保持原范围。
