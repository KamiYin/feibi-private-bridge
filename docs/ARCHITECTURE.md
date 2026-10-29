# 当前架构与工具

微信 getupdates → 本人来源检查 → 原子保存请求／游标 → 原 Events 订阅通知 → dot → MCP 回复 → 微信 sendmessage。

文字与附件元数据直接进入事件；文件读取与准备不持有文字轮询锁。未知 item 保留 type/content_available:false，其余可支持 item 按原顺序传递。桥接不会把未知类型当作已成功解析的图片。

## 发送与完成

| 工具 | 输入与语义 |
| --- | --- |
| reply_to_owner | request_id、text、idempotency_key |
| reply_with_files_to_owner | 上述字段及 files；宿主按 openai/fileParams 注入下载对象 |
| reply_with_owner_attachments | 上述字段及 attachments，每项为 request_id、attachment_id |
| send_to_owner | text、idempotency_key；最近真实本人 contextToken，无 request_id 或收件人 |
| mark_owner_requests_handled | request_ids 数组；不发送，不伪造 accepted |
| get_owner_request | request_id；含 handled、reply_status、附件／引用元数据 |
| list_pending_owner_requests | 无参数；排除 handled 与最近发送结果不确定的请求 |
| get_owner_attachment | request_id、attachment_id；可选 offset、length（字节） |
| relay_status / test_status | 安全状态和计数 |

三个 reply 工具支持可选 final、handled_request_ids。final:false 为进度；省略或 true 在 accepted 后完成当前请求。handled_request_ids 用于同次 accepted 回复覆盖的其他请求。每条不同消息用独立稳定 key；同次发送重试保持原 key 与参数。unknown 不能换 key 再发。只需结束处理而无需发送时使用 handled 工具。

旧 intents 迁入 sends；保留 latest intent 供原工具读取。原 sending 在重启时成为 unknown。已经删除的旧 contextToken 不伪造恢复。新回复保留请求上下文，因此完成后仍能跟进。主动发送复用最新真实上下文，不保证微信接受任意久远 token。

## 附件与存储

图片直接返回 image content；文件返回嵌入 resource/blob。大响应失败时用分段读取，客户端直接解码写文件。next_offset/eof 指示进度，不把大段 base64 放进模型正文。

原件下载缓存共用本地字节预算；默认 256 MiB 是实现的内存预算，不是微信官方上限。上传复用协议 MD5、AES 与已上传引用，不增加额外文件校验。宿主 file_id 复用下载结果；附件准备最多两份并行，最终数组保持原顺序。

加密快照仍同步保存，发送前持久记录保障崩溃后的幂等。窄读请求、减少 clone、无变化空轮询不保存；没有新数据库或监控服务。已完成引用内容缓存最多 100 条／4 MiB，未扩展为全文聊天档案。
