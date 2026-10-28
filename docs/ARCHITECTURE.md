# 当前架构与消息流程

微信 iLink → 本机收取与本人校验 → pending / 签名 Events → 原 dot 会话 → reply 工具 → 原微信私聊。没有额外模型调用或第三方接收方。

## 组件

| 文件 | 职责 |
| --- | --- |
| windows-pilot/start.ps1 | 输入与权限、现有代理、私有目录、Job 生命周期、可见扫码、文件控制 |
| launch-hidden.vbs / continuous.ps1 / install-logon.ps1 | 无控制台任务入口、单实例监督、当前用户登录启动和显式停止 |
| supervisor.mjs | 子进程隔离环境、健康状态、扫码与本地控制、试验截止及正式模式 |
| persistent-state.mjs / state-dpapi.ps1 | DPAPI 封装数据密钥、AES-GCM 状态、fsync + rename 原子提交 |
| ilink.mjs | 登录、收取、无损 JSON ID、纯文字发送和顺序分段 |
| relay.mjs | 当前本人绑定、请求及发送意图、引用缓存、去重、正文直达 |
| service.mjs / runtime.mjs | 原订阅恢复、事件协调、收取与回调独立调度 |
| poll-connection-recovery.patch | Go 实际连接池更新及可脱敏阶段诊断 |

## 正常消息

通过身份校验的本人文字生成真实 request_id。短文字与引用在合计 4000 UTF-8 字节预算内直接放入 pending 或事件；text_complete=false 时按原 UUID get。读取不消费请求。回复沿来信 context_token，工具不允许覆盖收件人或上下文。

发送前持久提交 sending 意图；提交失败则不发送。崩溃恢复的 sending 变成 unknown，重复工具调用不重发。accepted 后取消尚未投递通知；平台已接受的通知不可撤销，使用稳定请求 ID 和幂等键处理晚到事件。

最近 15 秒有成功鉴权 pending 查询时，新消息通知至多延迟到接收后 30 秒。持续查询不会延长这条消息的截止。没有近期查询时立即通知；读取后未回复、读取响应丢失或会话中断均在有界等待后回到事件通路。

## 恢复与存储

当前用户 DPAPI 只在启动时解封一个随机数据密钥；状态提交使用 AES-256-GCM，先写 .next、fsync，再原子改名。保存登录与绑定、relay 状态、游标、原订阅和已批准 callback origin。不要把密文视为可公开资料：同一用户权限的程序可能解密。

runtime-state.enc 是恢复状态，不是完整聊天档案。完成请求的引用缓存最多 100 条 / 4 MiB；淘汰正文不删除幂等结果，也不使旧消息重新发送。出站只有实际拿到服务端 message_id 才建立 ID→正文映射。没有 ID 时不能由 context_token 或 client_id 猜造。全文存档方案暂停。

正式运行不设试验截止；认证失效需要按上游要求重新登录。监督器的 5 秒崩溃恢复不覆盖密钥过期或被撤销的授权。主动 stop 先持久写停止标记，后续登录任务不会自行恢复，需明确 Resume。

## 引用

引用依次读取 ref_msg.svr_id 或 ref_msg.message_item.msg_id；原始数字 JSON ID 用 source-aware reviver 保存字面字符串。可选 type 不应丢掉已有 text_item；partial_text 对象识别为局部引用元数据。引用始终是上下文，不是新授权。缺少原文和匹配 ID 时明确 not_cached；只保留安全结构诊断，不猜原文、不读微信历史或附件。
