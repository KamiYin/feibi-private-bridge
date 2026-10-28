# 安装、运行与恢复

## 环境与源码检查

Windows x64、NTFS、PowerShell 5.1 STA、Node.js 24+。本仓库使用内置 Node 模块与已保留许可的二维码源码，不需要 npm install。选择自己可写的专用目录。公开副本不含 EXE、原平台 Tunnel、账号或已登录状态。

~~~powershell
npm test
npm run preflight
~~~

默认缺少二进制应报告 REVIEWED_BINARY_MISSING、launched=false、credential_read=false。测试使用合成数据和隔离临时目录；部署与测试不要混用真实凭据。

## 隧道运行时构建

上游：[openai/tunnel-client](https://github.com/openai/tunnel-client)，提交 274a5588414819f063d27100a4fb1096aae3830f（v0.0.18），原构建 Go 1.27.3 / windows-amd64 / CGO=0。先在独立上游源码目录准备依赖，依次应用两个补丁：

~~~powershell
git checkout 274a5588414819f063d27100a4fb1096aae3830f
git apply --check 'YOUR_BRIDGE_CHECKOUT\windows-pilot\origin-guard.patch'
git apply 'YOUR_BRIDGE_CHECKOUT\windows-pilot\origin-guard.patch'
git apply --check 'YOUR_BRIDGE_CHECKOUT\windows-pilot\poll-connection-recovery.patch'
git apply 'YOUR_BRIDGE_CHECKOUT\windows-pilot\poll-connection-recovery.patch'
$env:CGO_ENABLED='0'
$env:GOOS='windows'
$env:GOARCH='amd64'
$env:GOTOOLCHAIN='local'
go test ./pkg/controlplane/internal -run 'TestPollRecovery|TestPollPool|TestPollTrace' -count=1 -timeout=60s
go build -trimpath -buildvcs=false -ldflags '-s -w -X github.com/openai/tunnel-client/pkg/version.semanticVersion=0.0.18-local-poll-recovery.3 -X github.com/openai/tunnel-client/pkg/version.GitSHA=274a5588414819f063d27100a4fb1096aae3830f -X github.com/openai/tunnel-client/pkg/version.Flavor=runtime' -o tunnel-client-runtime-origin-guard.exe ./cmd/client-runtime
Get-FileHash .\tunnel-client-runtime-origin-guard.exe -Algorithm SHA256
~~~

原部署固定 SHA-256：e607591deed958e2e324a9246b2683c727405bcbe69164d45cc67137db5d4e5f。公开整理没有重新编译或证明逐字节可复现。自行构建须审阅来源、补丁及依赖后，在自己的派生版本更新预期哈希与记录，不应删除验证。核验后的 EXE 放 windows-pilot/bin/tunnel-client-runtime-origin-guard.exe（已忽略提交）。BUILD_PROVENANCE.json 和 binary-build-info.txt 为脱敏来源记录，保留第三方许可。

## 准备自己的平台与密钥

需要自己有权限的官方 Tunnel、原会话插件/Events 订阅，以及本人微信。原项目的标识和权限不随代码转让。三个官方来源仍走既有、相同的 HTTP(S) 代理；不要为示例关闭 TLS 或改系统安全配置。

在正常可见的本机 PowerShell 中使用隐藏输入保存专用 tunnel key；不要放入命令参数、聊天、仓库或 .env：

~~~powershell
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy RemoteSigned -File .\windows-pilot\start.ps1 -StoreCredential -CredentialExpiresUtc 'YOUR_ACTUAL_UTC_EXPIRY'
~~~

首次导入入口仍限制 30 天内的真实 UTC 到期（含毫秒），已有文件不覆盖；读取入口支持已审核元数据 never。原部署通过官方控制台将原 key 改为 Never 后，单独同步过其本地元数据，未更换 secret。这不意味着首次导入模板会自动延长服务端权限，或公开副本有自动轮换功能。使用者须按自己的官方期限配置；需要修改导入期限时应明确改自己的部署，而非伪造日期。

默认状态目录为当前用户 LocalAppData 下 FeibiPrivateBridge/credentials。tunnel-key.dpapi 保存专用 key，runtime-state-key.dpapi 保护恢复数据密钥，runtime-state.enc 保存登录与恢复状态。这些文件均属私密资料。同一 Windows 用户下有权限的进程可能解密；备份目录也应保持私有。打包应用环境可能虚拟化 LocalAppData，任务与首次导入必须指向同一实际位置。

## 首次长期运行

复制 windows-pilot/deployment.example.json 为 deployment.local.json，填写自己的 tunnel_id 和 owner_nonce。仅这份忽略提交的配置进入监督器，不保存 secret。

先以本人明确批准的范围启动一次，完成扫码绑定与原订阅：

~~~powershell
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy RemoteSigned -File .\windows-pilot\start.ps1 -Run -Standalone -Persistent -StoredCredential -ApprovePrivateTunnel -ApproveQrLogin -ApproveOwnerTextTransfer -ApproveOwnerReply -TunnelId 'YOUR_TUNNEL_ID' -OwnerNonce 'YOUR_OWNER_NONCE'
~~~

此入口使用已保存 key，后台启动；QR 单独显示。launch 回执不等于后端 ready，须核对 status。原会话订阅产生候选后，只批准核实过的官方 callback origin。执行 qr，待本人确认扫码后再 confirm；不要凭“扫码显示成功”自动绑定。使用下面的原控制入口：

~~~powershell
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy RemoteSigned -File .\windows-pilot\start.ps1 -ControlCommand status
# 同一入口的 ControlCommand 可取 approve / qr / confirm / stop
~~~

用本人文字完成真实往返验证，再协调无发送在途的交接。保留原订阅，不为每次重启重新创建订阅。

## 交给当前用户登录任务

正常 stop 旧实例并确认清理后，注册同一任务。安装脚本使用当前用户、Interactive、Limited，不安装系统服务：

~~~powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy RemoteSigned -File .\windows-pilot\install-logon.ps1
# 本次明确恢复时，移除自己状态目录中的 operator-stopped 标记后：
Start-ScheduledTask -TaskName FeibiPrivateBridge
Get-ScheduledTask -TaskName FeibiPrivateBridge
~~~

主动 stop 会保留停止标记，所以单纯 Start-ScheduledTask 不会偷偷重新启用。也可在明确要求恢复时，通过隐藏 PowerShell 运行 continuous.ps1 -Resume；与任务互斥保证单监督器。不要同时启动多个副本。

任务入口 wscript.exe //B //NoLogo → launch-hidden.vbs → 隐藏监督器 → CreateNoWindow 桥接子进程。文件控制仍可用；QR 需要时显示独立窗口。没有托盘或开机前服务。Windows Script Host 被禁用的机器需另行部署适用入口，当前发布不修改该策略。

## 验证恢复与升级

升级前确认没有发送在途；正常 stop，保留同一私有状态目录，更新代码，然后明确恢复原任务。核实 authenticated、owner_bound、callbacks_enabled，以及原订阅数量和 pending。sending 恢复成 unknown，不可为“补发”绕开幂等。认证失效可能仍需扫码。

原部署已实测任务接管、免扫码、原订阅及跨重启 pending 恢复。完整 Windows 登录和 dot 完整重启的端到端链路尚未单独实测；订阅有效期和平台调度仍由平台控制。卸载任务可在主动 stop 后通过 Windows 计划任务管理或 Unregister-ScheduledTask 处理；不要顺手删除私密状态或撤销其他应用凭据。

## 试验模式与当前边界

不传 Persistent 时仍有 1–43200 秒试验上限，可传原 DeadlineUtc 保持同一轮截止。正式模式不设试验硬截止，但真正网络超时、服务端权限、QR 有效期和私聊身份仍有效。长回复以 3500 UTF-8 字节保守分段，失败后不自动重发；仍有 HTTP 请求体/响应体资源边界。全文存档、媒体与历史拉取未实现。
