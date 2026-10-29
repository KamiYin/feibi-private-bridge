# 故障处理

0.2.0 的完整历史记录见 [历史证据归档](MILESTONE_02_EVIDENCE.md)；下文记录本版本状态。

- 新工具未显示：刷新原插件工具目录。服务已加载新 schema 不代表旧会话显示声明立即更新。不要把工具指令塞进文字参数绕过目录。
- reply_context_unavailable：旧回复可能已删除 token。等待新的本人消息提供真实上下文；不伪造 request 或 token。
- unknown：发送结果不能确定，保持原 key，不换 key 重发。业务已由另一条回复覆盖时可单独 handled，但不能改成发送成功。
- 大文件 Internal error／Transport closed：小文件可完整读取，大文件用 get_owner_attachment 的 offset/length，按 next_offset 继续并本地解码拼接。私有部署已用 4 MiB 分段接收大文件；不同宿主响应上限可能不同。
- media_origin_not_supported：查看仅 origin 的错误元数据，确认宿主实际官方文件域；不要公开完整签名下载链接。
- unsupported_items：桥接没有对应类型的解码。普通图片／文件仍可用；原生表情、GIF 动态展示不等于普通图片传输成功。
- 正常 stop 后不自动重启：operator-stopped 是显式停止标记，使用 continuous.ps1 -Resume 恢复。不要删除密钥或重建订阅来处理普通重连。
- REVIEWED_BINARY_MISSING：源码未附带 EXE，按部署文档构建自己的运行时。
