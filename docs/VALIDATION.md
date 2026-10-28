# 验证与验收

## 本次公开副本（0.2.0）

在 Windows 上实际运行 node --test weixin-candidate/*.test.mjs windows-pilot/*.test.mjs：**191 项通过，0 失败，0 跳过**，约 5.54 秒。包含纯合成协议/传输、relay、Events、运行时、Windows supervisor、隔离临时目录的 PS5 夹具与真实 CurrentUser DPAPI 合成往返。测试不使用实际登录、不调用真实微信、不改当前计划任务。

首轮公开测试出现 8 项旧夹具失败，原因是旧断言仍检查试验范围、前台 Normal、旧路径、错误的 Read-Host 分支和旧二维码模拟。修正测试以覆盖当前行为后，supervisor 60 项通过，随后完整 191 项通过；未删测试或把跳过算通过。

预检实际返回 REVIEWED_BINARY_MISSING、launched=false、credential_read=false，符合源码包不带 EXE 的形式。PowerShell 与脚本的合成运行在上述测试内覆盖。公开版安装的机器路径与配置适配经过源码检查；未用公开副本另起真实桥接。

## 原部署实测（与公开测试分开）

- 早期实际收信、reply accepted 与本人手机收取确认已完成；历史数据见时间线。
- .2 实际连接池更新后工具 get/reply 恢复；.3 首次自身 deadline 策略已部署。Go .3 针对命令 go test ./pkg/controlplane/internal -run 'TestPollRecovery|TestPollPool|TestPollTrace' -count=1 -timeout=60s 的原记录为 PASS 2.471s；本次公开未重跑 Go 构建。
- 正文直达在真实 Events/pending 中返回完整文字，无 get 调用；延迟有明显波动，详见性能页。
- 当前用户任务实际接管，免扫码恢复 owner 绑定、原 callback 与一个原订阅；重启前 pending 在恢复后成功处理。
- Hidden 无控制台任务运行，监督和桥接进程存在，检查时没有 Windows Terminal；QR 独立可见并完成绑定。
- 16:47 UTC，实际引用命中上一条出站原文，状态 cached，根据此回答并 accepted。没有用猜测替代引用原文。

## 尚未完成的场景

完整 Windows 重新登录、dot 应用完整重启后的端到端恢复尚未单独实测。桥接持久化和原订阅恢复不能保证平台永远及时唤醒。没有 24 小时稳定性或负载基准、媒体/文件/群聊、全文档案或自动历史查询验收。全文存档扩展按用户要求暂停。

accepted 表示上游受理，unknown 表示结果不确定且不得自动重放；除明确本人确认的样本外，不将 API accepted 自动写成手机显示成功。
