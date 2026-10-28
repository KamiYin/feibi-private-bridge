# 安装与部署

## 环境与可复现范围

本地目标环境为 Windows x64、NTFS、Windows PowerShell 5.1 STA、Node.js 24。桥接的 JavaScript 代码使用 Node 内置模块；二维码渲染器的必要源码已随库保留，不需要运行依赖安装脚本。

公开副本可以运行离线回归。它没有运行时 EXE，也没有服务器端 Tunnel、订阅和账号授权，不能下载后直接连入原部署。

```powershell
npm test
npm run preflight
```

预检只读本地包和二进制，不启动网络或扫码。本仓库默认返回 `REVIEWED_BINARY_MISSING`。不要把预检可运行与真实微信连接混为一谈。

## 隧道运行时来源与构建

原构建记录：OpenAI [tunnel-client](https://github.com/openai/tunnel-client)，v0.0.18，提交 `274a5588414819f063d27100a4fb1096aae3830f`；Go 1.27.3，Windows / amd64，CGO 关闭，trimpath。记录文件保留在 `windows-pilot/BUILD_PROVENANCE.json` 和 `binary-build-info.txt`。

在单独的上游源码目录中，按其官方构建环境准备依赖后应用本仓库补丁：

```powershell
git clone https://github.com/openai/tunnel-client.git
Set-Location tunnel-client
git checkout 274a5588414819f063d27100a4fb1096aae3830f
git apply --check 'YOUR_BRIDGE_CHECKOUT\windows-pilot\origin-guard.patch'
git apply 'YOUR_BRIDGE_CHECKOUT\windows-pilot\origin-guard.patch'
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:GOTOOLCHAIN = 'local'
go test ./pkg/controlplane/internal
go build -trimpath -o tunnel-client-runtime-origin-guard.exe ./cmd/client-runtime
Get-FileHash .\tunnel-client-runtime-origin-guard.exe -Algorithm SHA256
```

这些是从来源记录和入口文件整理的构建步骤，**本次公开整理没有重新编译 Go 运行时，也未证明重新构建可得到逐字节相同的 EXE**。原记录的离线构建还使用了 `GOPROXY=off`，前提是依赖缓存已备齐；不要把离线记录理解为首次构建不需要依赖。

启动器固定期望的原构建 SHA-256 是：

```text
30e10e36956085c6c73f88e30942d1b96c2645f1ad6cea3b7697cb2de5ce5c48
```

自行构建件与此不同会被拒绝。只有完成自己的源码、补丁、依赖和构建核验后，才应在自己的派生版本更新固定哈希、构建说明及相应测试；不要直接删除校验。通过核验的文件放到 `windows-pilot/bin/tunnel-client-runtime-origin-guard.exe`，该目录已忽略。公开仓库的预检测试按“不含二进制”的发行形式编写；本机添加二进制后，应单独运行真实预检并调整自己的发行测试。

## 本地配置

`.env.example` 仅说明配置入口，启动器不自动读取 `.env`。不要把密钥放入 `.env`、命令参数或仓库。

| 输入 | 配置方法 |
| --- | --- |
| Tunnel ID | 启动参数 `-TunnelId`，由自己的平台隧道配置取得 |
| 本轮本人确认值 | `-OwnerNonce`，使用与当前会话匹配的新值 |
| 隧道密钥 | 正常本机控制台隐藏输入；可选经明确授权的 DPAPI 存储入口 |
| 既有代理 | 启动器读取 Windows 当前代理或已有明确代理配置，不在仓库保存 |
| 回调订阅 | 在自己的原会话完成订阅；本地观察到候选后按现有流程 approve |
| 运行时长 | `-Seconds`，1–25200 秒；恢复同一轮时加原本的 `-DeadlineUtc` |

当前代理校验要求三个固定官方来源选中同一个 HTTP(S) 代理。DIRECT、不同代理、代理认证或不明确结果会被拒绝。不要为适配示例改系统网络、禁用 TLS 或关安全软件。

公开副本将原本机器专属的工作目录改成**仓库根目录**：每次启动在其下创建随机私有目录，并继续检查 NTFS、祖先目录和当前用户 ACL。选用自己可写的 NTFS 路径。

## 首次启动与本人扫码

先在正常本机 PowerShell 控制台完成预检。确认有自己的隧道、订阅与权限后，运行以下模板；`YOUR_...` 必须替换，模板本身不能直接运行：

```powershell
powershell.exe -NoLogo -NoProfile -STA -File .\windows-pilot\start.ps1 `
  -Run -Standalone `
  -ApprovePrivateTunnel -ApproveQrLogin -ApproveOwnerTextTransfer -ApproveOwnerReply `
  -TunnelId 'YOUR_TUNNEL_ID' -OwnerNonce 'YOUR_OWNER_NONCE' -Seconds 3600
```

1. 在本机受控输入提示中输入隧道密钥。不要把密钥发到聊天、日志或命令行参数。
2. `standalone_host_launched` 只是宿主窗口已创建。看到实际 `bounded_windows_started` 才表示后端启动；核对该回执中的截止时间。
3. 先在原会话确认事件订阅就绪，再查看本地 `status`。只对已观察并核验的官方回调来源执行 `approve`。
4. 执行 `qr`，二维码只在本机内存窗口显示，随后自动轮询。
5. 本人扫码后，在原会话明确确认本人扫码完成，再执行当轮 `confirm`。普通二维码过期可明确重新执行 `qr`，不能沿用旧身份确认。
6. 本人在微信发一条普通测试文字；核对来信事件、原会话读取、回复 API 回执，最后在手机确认。

不要在仍有同用户桥接运行时另起实例。这里的发布整理没有启动第二个桥接。

## 日常控制与停止

控制台支持 `status`、`approve`、`qr`、`poll`、`confirm`、`stop`。独立窗口不可定位时，可从同一项目用以下入口：

```powershell
powershell.exe -NoLogo -NoProfile -STA -File .\windows-pilot\start.ps1 -ControlCommand status
```

文件控制支持 status / approve / qr / confirm / stop，仍需满足原流程的身份确认和回调条件。运行结果文件包含本机状态和私有目录位置，只留本地，不提交。

`stop` 后核对停止与清理回执。关闭窗口不等于服务器端撤销账号授权或密钥；需要撤销时按各自官方界面处理。不要承诺进程崩溃或系统重启后免扫码恢复。

## 可选 DPAPI

经使用者明确决定，可用 `-StoreCredential -CredentialExpiresUtc 'YOUR_UTC_EXPIRY'` 在本机隐藏输入导入专用隧道密钥。到期时间须为毫秒精度 UTC，首次导入上限 30 天；已有文件不静默覆盖。后续实际运行加 `-StoredCredential`，并使用专用 PS5.1 STA File 宿主。

此入口采用 Windows 当前用户 DPAPI 与私有 ACL；不会保存微信令牌。缺失、解密失败、过期分别返回固定错误码。仓库不含 DPAPI 文件，本次整理也未重新导入、读取或替换真实密钥。
