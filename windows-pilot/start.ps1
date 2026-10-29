# Windows PowerShell 5.1 / Node 24 x64. Default is offline preflight only.
# Do not use ExecutionPolicy Bypass, Unrestricted, or IEX to run this script.
[CmdletBinding()]
param(
  [switch]$Run,
  [switch]$Persistent,
  [switch]$Standalone,
  [switch]$StandaloneChild,
  [switch]$ValidateStartupOnly,
  [switch]$NativeClipboard,
  [switch]$StoredCredential,
  [switch]$StoreCredential,
  [ValidateSet('','status','approve','qr','confirm','stop')][string]$ControlCommand = '',
  [string]$CredentialExpiresUtc = '',
  [switch]$ApprovePrivateTunnel,
  [switch]$ApproveQrLogin,
  [switch]$ApproveOwnerTextTransfer,
  [switch]$ApproveOwnerReply,
  [switch]$ApproveOwnerMedia,
  [string]$TunnelId = '',
  [string]$OwnerNonce = '',
  [string]$ExpectedSuffix = '',
  [ValidateRange(1,2147483647)][int]$Seconds = 43200,
  [string]$DeadlineUtc = ''
)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:process = $null
$script:job = [IntPtr]::Zero
$script:directory = $null
$script:qrForm = $null
$script:qrImage = $null
$script:qrDeadline = 0
$script:stopReceipt = $false
$script:cleanupConfirmed = $false
$script:jobClosed = $false
$script:supervisorExited = $false
$script:runtimeKey = $null
$script:secureKey = $null
$script:bstr = [IntPtr]::Zero
$script:controlInput = $null
$script:fileControlRequest = $null
$script:pending = $null
$script:stderr = $null
$script:writeOperation = $null
$script:pipeWriteFailed = $false
$script:activityClock = $null
$script:absoluteDeadline = $null
$script:instanceMutex = $null
$script:instanceOwned = $false
$script:startupStage = 'entry'
$script:confirmedDeadline = ''
$script:resultEvent = 'starting'
$script:resultCode = ''
$script:resultErrorType = ''
$script:exitCode = 0
$bootstrap = $null

function Assert-NativeStdinHost {
  if ($PSVersionTable.PSVersion.Major -ne 5 -or [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { throw 'NATIVE_STDIN_HOST_REQUIRED' }
  # Only an explicit, dedicated -File process may own stdin. In particular, no
  # -NoExit or abbreviated host flags may return remaining input to a shell.
  $arguments = [Environment]::GetCommandLineArgs()
  $fileFound = $false
  for ($index = 1; $index -lt $arguments.Length; $index++) {
    $flag = $arguments[$index].ToLowerInvariant()
    if (@('-nologo','-noprofile','-sta','-noninteractive') -ccontains $flag) { continue }
    if ($flag -ceq '-executionpolicy') {
      $index++
      if ($index -ge $arguments.Length -or $arguments[$index] -ine 'RemoteSigned') { throw 'NATIVE_STDIN_HOST_REQUIRED' }
      continue
    }
    if ($flag -ceq '-file' -and $index + 1 -lt $arguments.Length) {
      $fileFound = [IO.Path]::GetFullPath($arguments[$index + 1]).Equals([IO.Path]::GetFullPath($PSCommandPath),[StringComparison]::OrdinalIgnoreCase)
      break
    }
    throw 'NATIVE_STDIN_HOST_REQUIRED'
  }
  if (-not $fileFound) { throw 'NATIVE_STDIN_HOST_REQUIRED' }
}
function Assert-ControlInputOpen {
  if ($null -ne $script:absoluteDeadline -and [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge $script:absoluteDeadline) { throw 'TIME_LIMIT_REACHED' }
  if ($null -ne $script:controlInput) {
    $reason = $script:controlInput.StopReason
    if ($reason -ne '') { throw $reason }
  }
}
function Assert-NativeClipboardRetention {
  # Read only policy booleans. Never inspect content or change history/sync.
  try {
    $null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType=WindowsRuntime]
    $historyEnabled = [Windows.ApplicationModel.DataTransfer.Clipboard]::IsHistoryEnabled()
    $roamingEnabled = [Windows.ApplicationModel.DataTransfer.Clipboard]::IsRoamingEnabled()
    if ($historyEnabled -isnot [bool] -or $roamingEnabled -isnot [bool] -or $historyEnabled -or $roamingEnabled) { throw 'NATIVE_CLIPBOARD_RETENTION_BLOCKED' }
  } catch { throw 'NATIVE_CLIPBOARD_RETENTION_BLOCKED' }
}
function Receive-StopReceipt($Event) {
  if ($null -eq $Event -or $null -eq $Event.PSObject.Properties['event'] -or $Event.event -cne 'bounded_windows_stopped') { return $false }
  foreach ($name in @('children_exited','temporary_files_removed','account_authorization_revoked')) {
    if ($null -eq $Event.PSObject.Properties[$name] -or $Event.$name -isnot [bool]) { return $false }
  }
  if ($null -eq $Event.PSObject.Properties['reason'] -or $Event.reason -isnot [string] -or $Event.reason -cnotmatch '\A[A-Z][A-Z_]{0,63}\z') { return $false }
  $script:stopReceipt = $true
  $script:cleanupConfirmed = ($Event.children_exited -eq $true -and $Event.temporary_files_removed -eq $true -and $Event.reason -cne 'CLEANUP_UNCONFIRMED')
  return $true
}
function Stop-LocalQr {
  $script:qrDeadline = 0
  if ($null -ne $script:qrForm) { $script:qrForm.Close(); $script:qrForm.Dispose(); $script:qrForm = $null }
  if ($null -ne $script:qrImage) { $script:qrImage.Dispose(); $script:qrImage = $null }
}
function Quote-Argument([string]$Value) {
  if ($Value.Contains('"') -or $Value.EndsWith('\')) { throw 'UNSAFE_LAUNCH_PATH' }
  return '"' + $Value + '"'
}
function Write-StandaloneResult([string]$EventName,[string]$Code = '',[string]$ErrorType = '',$ExitCode = $null) {
  if (-not $StandaloneChild) { return }
  # One overwritten status object, never raw output, parameters or credentials.
  $result = [ordered]@{pid=$PID;event=$EventName;stage=$script:startupStage;error_type=$ErrorType;code=$Code;exit_code=$ExitCode;deadline_utc=$script:confirmedDeadline;control_directory=$script:directory}
  [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'standalone-result.json'),($result | ConvertTo-Json -Compress))
}

function Start-StandaloneHost {
  # A real local control console owns stdin and the cleanup Job. The tool PTY
  # only launches it; no input/output redirection or persistent service is used.
  $hostPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $argsText = '-NoLogo -NoProfile -STA -ExecutionPolicy RemoteSigned -File ' + (Quote-Argument $PSCommandPath) + ' -Run -StandaloneChild'
  foreach ($name in @('Persistent','NativeClipboard','StoredCredential','ApprovePrivateTunnel','ApproveQrLogin','ApproveOwnerTextTransfer','ApproveOwnerReply','ApproveOwnerMedia')) {
    if (Get-Variable -Name $name -ValueOnly) { $argsText += ' -' + $name }
  }
  $argsText += ' -TunnelId ' + (Quote-Argument $TunnelId) + ' -OwnerNonce ' + (Quote-Argument $OwnerNonce) + ' -Seconds ' + $Seconds
  if ($ExpectedSuffix -ne '') { $argsText += ' -ExpectedSuffix ' + (Quote-Argument $ExpectedSuffix) }
  if ($DeadlineUtc -ne '') { $argsText += ' -DeadlineUtc ' + (Quote-Argument $DeadlineUtc) }
  # Hidden dedicated console retains stdin and cleanup Job; operator uses file control.
  $hostProcess = Start-Process -FilePath $hostPath -ArgumentList $argsText -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -PassThru
  try {
    Write-Host ((@{event='standalone_host_launched';pid=$hostProcess.Id;backend_started=$false;control='local_file';window_style='Hidden';requested_deadline_utc=$DeadlineUtc;result_file=(Join-Path $PSScriptRoot 'standalone-result.json')} | ConvertTo-Json -Compress))
  } finally { $hostProcess.Dispose() }
}
function Enter-RunInstance {
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $script:instanceMutex = New-Object Threading.Mutex($false,('Local\FeibiPrivateBridge-local-reviewed-' + $sid))
  try { $script:instanceOwned = $script:instanceMutex.WaitOne(0) }
  catch [Threading.AbandonedMutexException] { $script:instanceOwned = $true }
  if (-not $script:instanceOwned) { throw 'BRIDGE_ALREADY_RUNNING' }
}

function Write-PrivateLine($Target,[string]$Value) {
  # Explicit UTF-8 bytes: Windows PowerShell/OEM codepages must not corrupt paths.
  $bytes = [Text.Encoding]::UTF8.GetBytes($Value + "`n")
  try {
    if ($null -ne $script:writeOperation -and -not $script:writeOperation.IsCompleted) { throw 'PRIVATE_PIPE_WRITE_FAILED' }
    Assert-ControlInputOpen
    if ($null -ne $script:activityClock -and $script:activityClock.Elapsed.TotalSeconds -ge $Seconds) { throw 'TIME_LIMIT_REACHED' }
    $script:writeOperation = [FeibiPipeWrite]::Start($Target.StandardInput.BaseStream,$bytes)
    $writeWait = [Diagnostics.Stopwatch]::StartNew()
    while (-not $script:writeOperation.IsCompleted) {
      if ($writeWait.ElapsedMilliseconds -ge 1000) { throw 'PRIVATE_PIPE_WRITE_FAILED' }
      Assert-ControlInputOpen
      if ($null -ne $script:activityClock) {
        if ($script:qrDeadline -gt 0 -and $script:activityClock.Elapsed.TotalSeconds -ge $script:qrDeadline) { Stop-LocalQr; Write-Host '{"event":"qr_closed","reason":"WINDOWS_QR_DEADLINE"}' }
        if ($script:activityClock.Elapsed.TotalSeconds -ge $Seconds) { throw 'TIME_LIMIT_REACHED' }
      }
      if ($null -ne $script:qrForm) { [Windows.Forms.Application]::DoEvents() }
      Start-Sleep -Milliseconds 10
    }
    if ($script:writeOperation.IsFaulted -or $script:writeOperation.IsCanceled -or -not $script:writeOperation.Result) { throw 'PRIVATE_PIPE_WRITE_FAILED' }
    $script:writeOperation = $null
  } catch {
    $script:pipeWriteFailed = ($null -ne $script:writeOperation)
    if ($script:pipeWriteFailed -and $null -eq $script:process) {
      # A routing-check child is not yet in the Job. Kill only this owned child.
      try { if (-not $Target.HasExited) { $Target.Kill(); $null = $Target.WaitForExit(1000) } } catch { }
    }
    throw
  } finally {
    # The .NET task owns pending buffers until actual I/O completion, including
    # failure. Never clear bytes still in use by an outstanding asynchronous write.
    if ($null -eq $script:writeOperation) { [Array]::Clear($bytes,0,$bytes.Length) }
    $bytes = $null
  }
}
function New-NodeProcess([string]$Mode) {
  $info = New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName = $script:nodePath
  $info.Arguments = (Quote-Argument (Join-Path $PSScriptRoot 'supervisor.mjs')) + ' ' + $Mode
  $info.WorkingDirectory = $PSScriptRoot
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $info.RedirectStandardInput = $true
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.EnvironmentVariables.Clear()
  $info.EnvironmentVariables['SystemRoot'] = $env:SystemRoot
  $info.EnvironmentVariables['WINDIR'] = $env:WINDIR
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $info
  if (-not $p.Start()) { throw 'NODE_START_FAILED' }
  return $p
}
function Get-ExistingRouting {
  # This may evaluate the user's existing PAC, so called only after explicit Run.
  $origins = @('https://api.openai.com','https://ilinkai.weixin.qq.com','https://connectors.api.openai.com')
  if ($ApproveOwnerMedia) { $origins += @('https://novac2c.cdn.weixin.qq.com','https://files.oaiusercontent.com','https://files.openai.com','https://sdmntprseasia.oaiusercontent.com') }
  $items = @()
  if (-not [string]::IsNullOrWhiteSpace($env:HTTPS_PROXY)) {
    $source = 'explicit-process-https-proxy'
    foreach ($origin in $origins) { $items += @{ origin = $origin; proxyUrl = $env:HTTPS_PROXY } }
  } else {
    $source = 'windows-default-web-proxy'
    $proxy = [System.Net.WebRequest]::DefaultWebProxy
    if ($null -eq $proxy) { throw 'EXISTING_PROXY_REQUIRED' }
    foreach ($origin in $origins) {
      $uri = [Uri]$origin
      if ($proxy.IsBypassed($uri)) { throw 'DIRECT_ROUTE_NOT_SUPPORTED' }
      $selected = $proxy.GetProxy($uri)
      if ($null -eq $selected -or $selected.AbsoluteUri -eq $uri.AbsoluteUri) { throw 'DIRECT_ROUTE_NOT_SUPPORTED' }
      $items += @{ origin = $origin; proxyUrl = $selected.AbsoluteUri }
    }
  }
  return @{ version = 1; source = $source; routes = $items }
}
function New-PrivateDirectory {
  $parent = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  if (-not [IO.Directory]::Exists($parent)) { throw 'PROJECT_DIRECTORY_REQUIRED' }
  $parent = [IO.Path]::GetFullPath($parent)
  $drive = New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($parent))
  if ($drive.DriveFormat -ne 'NTFS') { throw 'NTFS_REQUIRED' }
  $ancestor = New-Object IO.DirectoryInfo $parent
  while ($null -ne $ancestor) {
    if (($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_DIRECTORY_REJECTED' }
    $ancestor = $ancestor.Parent
  }
  # A PowerShell 7 parent may leave incompatible module search paths in Windows PowerShell.
  # Import the current engine's built-in security module normally, without changing those paths.
  Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Scope Local -ErrorAction Stop
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetOwner($sid)
  $acl.SetAccessRuleProtection($true,$false)
  $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
  $directory = Join-Path $parent ('feibi-private-' + [Guid]::NewGuid().ToString('N'))
  $null = [IO.Directory]::CreateDirectory($directory,$acl)
  # Register ownership before ACL readback so any later failure reaches the existing empty-only cleanup.
  $script:directory = $directory
  $check = Get-Acl -LiteralPath $directory
  $rules = @($check.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if (-not $check.AreAccessRulesProtected -or $check.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') {
    [IO.Directory]::Delete($directory,$false)
    throw 'PRIVATE_ACL_VERIFICATION_FAILED'
  }
  return $directory
}
function Show-LocalQr([string]$Encoded) {
  if ([string]::IsNullOrEmpty($Encoded) -or $Encoded.Length -gt 1398104 -or $Encoded -cnotmatch '^[A-Za-z0-9+/]*={0,2}$') { throw 'QR_DATA_REJECTED' }
  Stop-LocalQr
  # Private redirected pipe -> memory bitmap only. No PNG file, browser or upload.
  $bytes = [Convert]::FromBase64String($Encoded)
  $stream = New-Object IO.MemoryStream(,$bytes)
  try {
    $decoded = [Drawing.Image]::FromStream($stream)
    try { $script:qrImage = New-Object Drawing.Bitmap $decoded } finally { $decoded.Dispose() }
  } finally { $stream.Dispose(); [Array]::Clear($bytes,0,$bytes.Length); $bytes = $null }
  $script:qrForm = New-Object Windows.Forms.Form
  $script:qrForm.Text = 'Feibi - private Weixin QR (this device only)'
  $script:qrForm.ClientSize = New-Object Drawing.Size(560,560)
  $box = New-Object Windows.Forms.PictureBox
  $box.Dock = 'Fill'
  $box.SizeMode = 'Zoom'
  $box.Image = $script:qrImage
  $script:qrForm.Controls.Add($box)
  # The hidden console STARTUPINFO can suppress the first native ShowWindow.
  # This top-level QR form has no console owner. Explicitly restore only its HWND.
  if (-not ('FeibiQrWindow' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FeibiQrWindow {
 [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int command);
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
}
'@
  }
  $script:qrForm.StartPosition = 'CenterScreen'
  $script:qrForm.ShowInTaskbar = $true
  $script:qrForm.WindowState = 'Normal'
  $script:qrForm.Show()
  $null = [FeibiQrWindow]::ShowWindow($script:qrForm.Handle,1)
  $null = [FeibiQrWindow]::ShowWindow($script:qrForm.Handle,9)
  $script:qrForm.BringToFront()
  $script:qrForm.Activate()
  $null = [FeibiQrWindow]::SetForegroundWindow($script:qrForm.Handle)
  [Windows.Forms.Application]::DoEvents()
}
function Invoke-FileControl([string]$Command) {
  $receiptPath = Join-Path $PSScriptRoot 'standalone-result.json'
  $receipt = [IO.File]::ReadAllText($receiptPath) | ConvertFrom-Json
  if ($receipt.event -cne 'started' -or $null -eq (Get-Process -Id $receipt.pid -ErrorAction SilentlyContinue)) { throw 'LOCAL_CONTROL_UNAVAILABLE' }
  $directory = [IO.Path]::GetFullPath($receipt.control_directory)
  $temporaryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\') + '\'
  if (-not $directory.StartsWith(($temporaryRoot + 'feibi-private-'),[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetDirectoryName($directory).TrimEnd('\') -ine $temporaryRoot.TrimEnd('\')) { throw 'LOCAL_CONTROL_UNAVAILABLE' }
  Assert-CredentialPrivatePath $directory $true
  $null = Get-CredentialExpiry $receipt.deadline_utc
  $requestId = [Guid]::NewGuid().ToString('N')
  $requestPath = Join-Path $directory 'operator-request.json'
  $responsePath = Join-Path $directory ('operator-' + $requestId + '.json')
  $stagingPath = Join-Path $directory ('operator-' + $requestId + '.tmp')
  try {
    [IO.File]::WriteAllText($stagingPath,(@{id=$requestId;command=$Command} | ConvertTo-Json -Compress))
    if ([IO.File]::Exists($requestPath)) { throw 'LOCAL_CONTROL_BUSY' }
    [IO.File]::Move($stagingPath,$requestPath)
    $wait = [Diagnostics.Stopwatch]::StartNew()
    $responseWaitSeconds = if ($Command -ceq 'qr') { 30 } else { 10 }
    while ($wait.Elapsed.TotalSeconds -lt $responseWaitSeconds) {
      if ([IO.File]::Exists($responsePath)) {
        $response = [IO.File]::ReadAllText($responsePath) | ConvertFrom-Json
        if ($response.id -cne $requestId) { throw 'INVALID_OPERATOR_CONTROL' }
        Write-Host ($response | ConvertTo-Json -Depth 12 -Compress)
        return
      }
      if ($Command -ceq 'stop') {
        $finished = [IO.File]::ReadAllText($receiptPath) | ConvertFrom-Json
        if ($finished.pid -eq $receipt.pid -and $finished.event -ceq 'stopped') {
          Write-Host ((@{event='stopped';pid=$finished.pid;code=$finished.code;deadline_utc=$finished.deadline_utc} | ConvertTo-Json -Compress)); return
        }
      }
      Start-Sleep -Milliseconds 50
    }
    throw 'LOCAL_CONTROL_TIMEOUT'
  } finally {
    foreach ($file in @($stagingPath,$responsePath)) { if ([IO.File]::Exists($file)) { [IO.File]::Delete($file) } }
  }
}
function Receive-FileControl {
  if (-not $StandaloneChild -or $null -ne $script:fileControlRequest) { return }
  $requestPath = Join-Path $script:directory 'operator-request.json'
  if (-not [IO.File]::Exists($requestPath)) { return }
  $request = [IO.File]::ReadAllText($requestPath) | ConvertFrom-Json
  [IO.File]::Delete($requestPath)
  if ($request.id -cnotmatch '\A[a-f0-9]{32}\z' -or @('status','approve','qr','confirm','stop') -cnotcontains $request.command) { throw 'INVALID_OPERATOR_CONTROL' }
  $script:fileControlRequest = $request
  Send-Control $request.command
}
function Write-FileControlResult($Event) {
  if ($null -eq $script:fileControlRequest) { return }
  $expectedAction = @{status='status';approve='approve_callback';qr='qr_start';confirm='confirm_owner';stop='stop'}[$script:fileControlRequest.command]
  if ($Event.event -ceq 'operator_result' -and $Event.action -ceq $expectedAction) {
    $response = @{id=$script:fileControlRequest.id;event='operator_result';action=$Event.action;result=$Event.result}
  } elseif ($Event.event -ceq 'operator_rejected') {
    $response = @{id=$script:fileControlRequest.id;event='operator_rejected';code=$Event.reason}
  } else { return }
  # Supervisor already projects these events to nonsecret status and fixed codes.
  $responsePath = Join-Path $script:directory ('operator-' + $script:fileControlRequest.id + '.json')
  $temporaryPath = $responsePath + '.tmp'
  [IO.File]::WriteAllText($temporaryPath,($response | ConvertTo-Json -Depth 12 -Compress))
  [IO.File]::Move($temporaryPath,$responsePath)
  $script:fileControlRequest = $null
}

function Get-FeibiCredentialPath {
  return Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FeibiPrivateBridge\credentials\tunnel-key.dpapi'
}
function Get-CredentialExpiry([string]$Value) {
  if ($Value -ceq 'never') { return [DateTimeOffset]::Parse('9999-12-31T23:59:59.000Z') }
  $expiry = [DateTimeOffset]::MinValue
  if (-not [DateTimeOffset]::TryParseExact($Value,"yyyy-MM-dd'T'HH:mm:ss.fff'Z'",[Globalization.CultureInfo]::InvariantCulture,([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal),[ref]$expiry)) { throw 'STORED_CREDENTIAL_INVALID' }
  if ($expiry -le [DateTimeOffset]::UtcNow) { throw 'STORED_CREDENTIAL_EXPIRED' }
  return $expiry
}
function Assert-CredentialPrivatePath([string]$Path,[bool]$ProtectedDirectory) {
  Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Scope Local -ErrorAction Stop
  if (((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'STORED_CREDENTIAL_NOT_PRIVATE' }
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl = Get-Acl -LiteralPath $Path
  $rules = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
  if (($ProtectedDirectory -and -not $acl.AreAccessRulesProtected) -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or $rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') { throw 'STORED_CREDENTIAL_NOT_PRIVATE' }
}
function Initialize-FeibiCredentialDirectory {
  $directory = [IO.Path]::GetDirectoryName((Get-FeibiCredentialPath))
  if (-not [IO.Directory]::Exists($directory)) {
    $parent = [IO.Path]::GetDirectoryName($directory)
    if ([IO.Directory]::Exists($parent) -and ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'STORED_CREDENTIAL_NOT_PRIVATE' }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid); $acl.SetAccessRuleProtection($true,$false)
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    $null = [IO.Directory]::CreateDirectory($directory,$acl)
  }
  Assert-CredentialPrivatePath $directory $true
}
function Save-FeibiCredential([Security.SecureString]$Key,[string]$ExpiresUtc) {
  $expiry = Get-CredentialExpiry $ExpiresUtc
  if ($expiry -gt [DateTimeOffset]::UtcNow.AddDays(30)) { throw 'STORED_CREDENTIAL_INVALID' }
  Initialize-FeibiCredentialDirectory
  $path = Get-FeibiCredentialPath
  if ([IO.File]::Exists($path)) { throw 'STORED_CREDENTIAL_ALREADY_EXISTS' }
  Add-Type -AssemblyName System.Security
  $pointer = [IntPtr]::Zero; $plain = $null; $bytes = $null; $encrypted = $null; $file = $null; $created = $false; $saved = $false
  try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ($plain -cnotmatch '\Ask-[A-Za-z0-9_-]{20,1021}\z') { throw 'STORED_CREDENTIAL_INVALID' }
    $bytes = [Text.Encoding]::UTF8.GetBytes((@{version=1;key=$plain;expires_utc=$ExpiresUtc} | ConvertTo-Json -Compress))
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $file = New-Object IO.FileStream($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $created = $true; $file.Write($encrypted,0,$encrypted.Length); $file.Dispose(); $file = $null
    Assert-CredentialPrivatePath $path $false
    $saved = $true
    return @{saved=$true;storage='windows_dpapi_current_user';expires_utc=$ExpiresUtc}
  } finally {
    if ($null -ne $file) { $file.Dispose() }
    if ($created -and -not $saved) { [IO.File]::Delete($path) }
    if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($null -ne $bytes) { [Array]::Clear($bytes,0,$bytes.Length) }
    if ($null -ne $encrypted) { [Array]::Clear($encrypted,0,$encrypted.Length) }
    $plain = $null
  }
}
function Read-FeibiCredential {
  $path = Get-FeibiCredentialPath
  if (-not [IO.File]::Exists($path)) { throw 'STORED_CREDENTIAL_MISSING' }
  Assert-CredentialPrivatePath ([IO.Path]::GetDirectoryName($path)) $true
  Assert-CredentialPrivatePath $path $false
  if ((Get-Item -LiteralPath $path).Length -gt 16384) { throw 'STORED_CREDENTIAL_INVALID' }
  Add-Type -AssemblyName System.Security
  $encrypted = $null; $bytes = $null; $payload = $null
  try {
    $encrypted = [IO.File]::ReadAllBytes($path)
    try { $bytes = [Security.Cryptography.ProtectedData]::Unprotect($encrypted,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser) }
    catch { throw 'STORED_CREDENTIAL_DECRYPT_FAILED' }
    try { $payload = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json }
    catch { throw 'STORED_CREDENTIAL_INVALID' }
    if ($null -eq $payload -or $null -eq $payload.PSObject.Properties['version'] -or $null -eq $payload.PSObject.Properties['key'] -or $null -eq $payload.PSObject.Properties['expires_utc'] -or $payload.version -ne 1 -or $payload.key -isnot [string] -or $payload.key -cnotmatch '\Ask-[A-Za-z0-9_-]{20,1021}\z') { throw 'STORED_CREDENTIAL_INVALID' }
    $expiry = Get-CredentialExpiry $payload.expires_utc
    $secure = New-Object Security.SecureString
    foreach ($character in $payload.key.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    return [pscustomobject]@{key=$secure;expires_utc=$payload.expires_utc}
  } finally {
    if ($null -ne $payload) { if ($null -ne $payload.PSObject.Properties['key']) { $payload.key = $null }; $payload = $null }
    if ($null -ne $bytes) { [Array]::Clear($bytes,0,$bytes.Length) }
    if ($null -ne $encrypted) { [Array]::Clear($encrypted,0,$encrypted.Length) }
  }
}

function Send-Control([string]$Command) {
  $value = $null
  switch ($Command.Trim().ToLowerInvariant()) {
    'status'  { $value = @{action='status'} }
    'qr'      { $value = @{action='qr_start'} }
    'poll'    { $value = @{action='qr_poll'} }
    'confirm' { $value = @{action='confirm_owner';nonce=$OwnerNonce;user_confirmed_scan=$true} }
    'approve' { $value = @{action='approve_callback';origin='https://connectors.api.openai.com'} }
    'stop'    { if ($Persistent) { [IO.File]::WriteAllText((Join-Path ([IO.Path]::GetDirectoryName((Get-FeibiCredentialPath))) 'operator-stopped'),'stopped') }; $value = @{action='stop'} }
    default  { Write-Host 'Commands: status | approve | qr | poll | confirm | stop'; return }
  }
  Write-PrivateLine $script:process ($value | ConvertTo-Json -Compress)
}
try {
  Write-StandaloneResult 'starting'
  $script:startupStage = 'preflight'
  if ($ControlCommand -ne '') {
    if ($Run -or $Standalone -or $StandaloneChild -or $StoreCredential -or $StoredCredential -or $NativeClipboard) { throw 'INVALID_RUN_PARAMETERS' }
    Invoke-FileControl $ControlCommand; return
  }
  if ($StandaloneChild -and (-not $Run -or $Standalone)) { throw 'INVALID_RUN_PARAMETERS' }
  if ($Standalone -and (-not $Run -or $ValidateStartupOnly)) { throw 'INVALID_RUN_PARAMETERS' }
  if ($ValidateStartupOnly -and -not $Run) { throw 'STARTUP_VALIDATION_REQUIRES_RUN' }
  if ($StoredCredential -and (-not $Run -or $NativeClipboard -or $StoreCredential)) { throw 'INVALID_RUN_PARAMETERS' }
  if ($StoreCredential) {
    if ($Run -or $Standalone -or $StandaloneChild -or $ValidateStartupOnly) { throw 'INVALID_RUN_PARAMETERS' }
    $script:startupStage = 'credential_store'
    $null = Get-CredentialExpiry $CredentialExpiresUtc
    if ($NativeClipboard) {
      Assert-NativeStdinHost; Assert-NativeClipboardRetention
      Add-Type -AssemblyName System.Windows.Forms
      $script:runtimeKey = [Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::UnicodeText)
      $script:secureKey = New-Object Security.SecureString
      foreach ($character in $script:runtimeKey.ToCharArray()) { $script:secureKey.AppendChar($character) }
      $script:runtimeKey = $null; $script:secureKey.MakeReadOnly()
    } else {
      if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { throw 'INTERACTIVE_NATIVE_CONSOLE_REQUIRED' }
      [Console]::Title = 'Feibi - One-time encrypted key setup'
      $script:secureKey = Read-Host 'Paste approved tunnel key for user-encrypted storage (hidden)' -AsSecureString
    }
    $saved = Save-FeibiCredential $script:secureKey $CredentialExpiresUtc
    Write-Host ((@{event='credential_saved';storage=$saved.storage;expires_utc=$saved.expires_utc} | ConvertTo-Json -Compress))
    return
  }
  if ($NativeClipboard -and -not $Run) { throw 'NATIVE_STDIN_REQUIRES_RUN' }
  if ($PSVersionTable.PSVersion.Major -lt 5 -or [Environment]::OSVersion.Platform -ne 'Win32NT' -or -not [Environment]::Is64BitProcess) { throw 'WINDOWS_X64_POWERSHELL_REQUIRED' }
  $script:nodePath = (Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
  if (-not [IO.Path]::IsPathRooted($script:nodePath)) { throw 'ABSOLUTE_NODE_PATH_REQUIRED' }
  $preflight = New-NodeProcess '--preflight'
  try {
    $output = $preflight.StandardOutput.ReadToEnd()
    $null = $preflight.StandardError.ReadToEnd()
    $preflight.WaitForExit()
    $report = $output | ConvertFrom-Json
    Write-Host $output.Trim()
    if (-not $Run) { return }
    if (-not $report.can_prepare_run) { throw 'PREFLIGHT_BLOCKED' }
  } finally { $preflight.Dispose() }
  if (-not ($ApprovePrivateTunnel -and $ApproveQrLogin -and $ApproveOwnerTextTransfer -and $ApproveOwnerReply)) { throw 'EXPLICIT_ACTION_APPROVAL_REQUIRED' }
  if ($TunnelId -notmatch '^tunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}$' -or $OwnerNonce -notmatch '^bind:[A-Za-z0-9_-]{16,80}$' -or ($ExpectedSuffix -ne '' -and $ExpectedSuffix -cnotmatch '^[A-Za-z0-9_-]{4}$')) { throw 'INVALID_RUN_PARAMETERS' }
  if ($DeadlineUtc -ne '') {
    $parsedDeadline = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact($DeadlineUtc, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$parsedDeadline)) { throw 'INVALID_RUN_PARAMETERS' }
    $script:absoluteDeadline = $parsedDeadline.ToUnixTimeMilliseconds()
    Assert-ControlInputOpen
  }
  if ($Standalone) { Start-StandaloneHost; return }
  $script:startupStage = 'native_host'
  Enter-RunInstance
  if (-not [Console]::IsOutputRedirected) { [Console]::Title = 'Feibi Private Bridge - local control - type stop to exit' }
  if ($NativeClipboard) { Assert-NativeStdinHost; Assert-NativeClipboardRetention }
  elseif ($StoredCredential) { Assert-NativeStdinHost }
  elseif ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { throw 'INTERACTIVE_NATIVE_CONSOLE_REQUIRED' }
  # Available before routing-check's first private write. No PowerShell callback
  # runs on a worker thread; buffer cleanup happens only after completed I/O.
  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading.Tasks;
public static class FeibiPipeWrite {
 public static Task<bool> Start(Stream stream,byte[] bytes) {
  if(stream == null || bytes == null) throw new ArgumentNullException();
  return Task.Run(async delegate {
   try {
    await stream.WriteAsync(bytes,0,bytes.Length).ConfigureAwait(false);
    await stream.FlushAsync().ConfigureAwait(false);
    return true;
   } catch { return false; }
   finally { Array.Clear(bytes,0,bytes.Length); }
  });
 }
}
'@
  $script:startupStage = 'routing'
  $routing = Get-ExistingRouting
  $routingArguments = '--routing-check'
  if ($ApproveOwnerMedia) { $routingArguments += ' --media' }
  $routingCheck = New-NodeProcess $routingArguments
  try {
    Write-PrivateLine $routingCheck ($routing | ConvertTo-Json -Depth 6 -Compress); $routingCheck.StandardInput.Close()
    $routingResult = $routingCheck.StandardOutput.ReadToEnd() | ConvertFrom-Json
    $null = $routingCheck.StandardError.ReadToEnd(); $routingCheck.WaitForExit()
    if ($routingCheck.ExitCode -ne 0 -or $routingResult.event -ne 'routing_validated') {
      if ($routingResult.reason -cmatch '^WINDOWS_[A-Z_]{1,64}$') { Write-Host ($routingResult | ConvertTo-Json -Compress) }
      throw 'EXISTING_PROXY_REQUIRED'
    }
  } finally { $routingCheck.Dispose() }
  $script:startupStage = 'private_directory'
  $script:directory = New-PrivateDirectory
  # A private kill-on-close Job Object owns only this supervisor and its children.
  # Assignment occurs before entering or sending a credential. Failure stops closed.
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FeibiJob {
 [StructLayout(LayoutKind.Sequential)] struct BASIC { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
 [StructLayout(LayoutKind.Sequential)] struct IO { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
 [StructLayout(LayoutKind.Sequential)] struct EXT { public BASIC BasicLimitInformation; public IO IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr a,string n);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr j,int c,IntPtr p,uint l);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool AssignProcessToJobObject(IntPtr j,IntPtr p);
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
 public static IntPtr Create() { IntPtr h=CreateJobObject(IntPtr.Zero,null); if(h==IntPtr.Zero) return h; EXT e=new EXT(); e.BasicLimitInformation.LimitFlags=0x2000; int size=Marshal.SizeOf(typeof(EXT)); IntPtr p=Marshal.AllocHGlobal(size); try { Marshal.StructureToPtr(e,p,false); if(!SetInformationJobObject(h,9,p,(uint)size)) { CloseHandle(h); return IntPtr.Zero; } return h; } finally { Marshal.FreeHGlobal(p); } }
}
'@
  # One bounded, background stdin reader. It never invokes PowerShell, reads
  # clipboard data, or handles credentials. The STA thread remains responsive.
  if ($NativeClipboard -or $StoredCredential) { Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Threading;
public sealed class FeibiControlInput : IDisposable {
 private readonly Stream input;
 private readonly object gate = new object();
 private readonly Queue<string> queue = new Queue<string>();
 private readonly Thread reader;
 private string line = "", stopReason = "";
 private bool afterCR, disposed;
 public FeibiControlInput(Stream source) {
  if (source == null) throw new ArgumentNullException("source");
  input = source; reader = new Thread(Pump); reader.IsBackground = true;
 }
 public string StopReason { get { lock(gate) return stopReason; } }
 public void Start() { reader.Start(); }
 public bool TryTake(out string command) {
  lock(gate) { command = null; if(disposed || stopReason != "" || queue.Count == 0) return false; command = queue.Dequeue(); return true; }
 }
 private void Stop(string reason) { lock(gate) { if(stopReason == "") stopReason = reason; line = ""; queue.Clear(); } }
 private bool Accept(byte value) {
  lock(gate) {
   if(disposed || stopReason != "") return false;
   if(value == 10 && afterCR) { afterCR = false; return true; }
   afterCR = false;
   if(value == 10 || value == 13) {
    afterCR = value == 13;
    string command = line; line = "";
    if(command == "stop") { Stop("OPERATOR_STOP"); return false; }
    if(command != "status" && command != "approve" && command != "qr" && command != "poll" && command != "confirm") { Stop("INVALID_OPERATOR_CONTROL"); return false; }
    if(queue.Count >= 16) { Stop("INPUT_BOUND_STOP"); return false; }
    queue.Enqueue(command); return true;
   }
   if(value < 97 || value > 122) { Stop("INVALID_OPERATOR_CONTROL"); return false; }
   if(line.Length >= 7) { Stop("INPUT_BOUND_STOP"); return false; }
   line += (char)value; return true;
  }
 }
 private void Pump() {
  byte[] bytes = new byte[64];
  try {
   while(true) {
    lock(gate) { if(disposed || stopReason != "") return; }
    int count = input.Read(bytes,0,bytes.Length);
    if(count == 0) { Stop("CONTROL_PIPE_CLOSED"); return; }
    for(int i = 0; i < count; i++) if(!Accept(bytes[i])) return;
   }
  } catch { Stop("CONTROL_PIPE_CLOSED"); }
  finally { Array.Clear(bytes,0,bytes.Length); }
 }
 public void Dispose() {
  lock(gate) { disposed = true; line = ""; queue.Clear(); }
  // Do not join a potentially blocked standard-input read. This background
  // thread cannot keep the dedicated, non-NoExit process alive after cleanup.
 }
}
'@
  }
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  $script:job = [FeibiJob]::Create()
  if ($script:job -eq [IntPtr]::Zero) { throw 'WINDOWS_JOB_REQUIRED' }
  if ($ValidateStartupOnly) {
    Write-Host '{"event":"startup_validated","validation_scope":"before_credentials","credential_read":false,"managed_supervisor_started":false}'
    return
  }
  if ($NativeClipboard -or $StoredCredential) {
    $script:controlInput = New-Object FeibiControlInput ([Console]::OpenStandardInput())
    $script:controlInput.Start()
  }
  $script:startupStage = 'supervisor_start'
  $script:process = New-NodeProcess '--managed'
  if (-not [FeibiJob]::AssignProcessToJobObject($script:job,$script:process.Handle)) { throw 'WINDOWS_JOB_ASSIGNMENT_FAILED' }
  $script:pending = $script:process.StandardOutput.ReadLineAsync()
  $script:stderr = $script:process.StandardError.ReadToEndAsync()
  $startupWait = [Diagnostics.Stopwatch]::StartNew()
  while (-not $script:pending.IsCompleted) {
    Assert-ControlInputOpen
    if ($script:process.HasExited -or $startupWait.Elapsed.TotalSeconds -ge 10) { throw 'SUPERVISOR_NOT_READY' }
    [Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 25
  }
  $waiting = $script:pending.GetAwaiter().GetResult()
  $script:pending = $null
  if ($waiting -ne '{"event":"supervisor_waiting_for_approved_bootstrap"}') { throw 'SUPERVISOR_NOT_READY' }
  $script:startupStage = 'credential_check'
  try {
    if ($NativeClipboard) {
      Assert-ControlInputOpen
      Assert-NativeClipboardRetention
      $script:runtimeKey = [Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::UnicodeText)
      Assert-ControlInputOpen
    } elseif ($StoredCredential) {
      $stored = Read-FeibiCredential
      $script:secureKey = $stored.key
      $credentialDeadline = (Get-CredentialExpiry $stored.expires_utc).ToUnixTimeMilliseconds()
      if ($null -eq $script:absoluteDeadline -or $credentialDeadline -lt $script:absoluteDeadline) { $script:absoluteDeadline = $credentialDeadline }
      $DeadlineUtc = [DateTimeOffset]::FromUnixTimeMilliseconds($script:absoluteDeadline).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
      $stored.key = $null; $stored = $null
      $script:bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:secureKey)
      $script:runtimeKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($script:bstr)
    } else {
      $script:secureKey = Read-Host 'Paste approved one-day Tunnels Read/Use key (hidden)' -AsSecureString
      $script:bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:secureKey)
      $script:runtimeKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($script:bstr)
    }
    if ($script:runtimeKey -cnotmatch '\Ask-[A-Za-z0-9_-]{20,1021}\z' -or ($ExpectedSuffix -ne '' -and -not $script:runtimeKey.EndsWith($ExpectedSuffix,[StringComparison]::Ordinal))) { throw 'KEY_PASTE_CHECK_FAILED' }
    $bootstrap = @{action='bootstrap';runtime_key=$script:runtimeKey;expected_suffix=$ExpectedSuffix;tunnel_id=$TunnelId;nonce=$OwnerNonce;seconds=$Seconds;directory=$script:directory;routing_snapshot=$routing;acl_verified=$true;tunnel_approved=$true;qr_approved=$true;text_transfer_approved=$true;reply_approved=$true}
    if ($ApproveOwnerMedia) { $bootstrap.media_approved = $true }
    if ($Persistent) {
      Initialize-FeibiCredentialDirectory
      $stateDir = [IO.Path]::GetDirectoryName((Get-FeibiCredentialPath))
      $bootstrap.persistent = $true; $bootstrap.state_directory = $stateDir
      $Seconds = [int]::MaxValue
      $bootstrap.seconds = $Seconds
    }
    if ($DeadlineUtc -ne '') { $bootstrap.deadline_utc = $DeadlineUtc }
    Assert-ControlInputOpen
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $script:activityClock = $clock
    $script:startupStage = 'bootstrap'
    Write-PrivateLine $script:process ($bootstrap | ConvertTo-Json -Depth 6 -Compress)
  } finally {
    if ($null -ne $bootstrap) { $bootstrap.runtime_key = ''; $bootstrap = $null }
    $script:runtimeKey = $null
    if ($script:bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($script:bstr); $script:bstr = [IntPtr]::Zero }
    if ($null -ne $script:secureKey) { $script:secureKey.Dispose(); $script:secureKey = $null }
  }
  Write-Host 'Commands: status | approve | qr | poll | confirm | stop'
  Write-Host 'confirm only after you explicitly confirm in the current dot chat that you scanned this QR yourself.'
  $script:pending = $script:process.StandardOutput.ReadLineAsync()
  $line = ''
  while (-not $script:process.HasExited -or $script:pending.IsCompleted) {
    Assert-ControlInputOpen
    Receive-FileControl
    if ($script:qrDeadline -gt 0 -and $clock.Elapsed.TotalSeconds -ge $script:qrDeadline) { Stop-LocalQr; Write-Host '{"event":"qr_closed","reason":"WINDOWS_QR_DEADLINE"}' }
    if (-not $Persistent -and $clock.Elapsed.TotalSeconds -ge $Seconds) { Write-Host '{"event":"windows_deadline_reached"}'; break }
    if ($script:pending.IsCompleted) {
      $message = $script:pending.GetAwaiter().GetResult()
      $script:pending = $null
      if ($null -eq $message) { break }
      $event = $message | ConvertFrom-Json
      if ($event.event -eq 'private_qr_png') {
        $remaining = [Math]::Min([double]$event.expires_within_seconds,([double]$event.expires_at_unix_ms - [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) / 1000)
        if (-not $Persistent) { $remaining = [Math]::Min($remaining,$Seconds - $clock.Elapsed.TotalSeconds) }
        if ($remaining -le 0 -or $remaining -gt 300) { $event.png_base64 = ''; $message = $null; throw 'QR_DATA_REJECTED' }
        Show-LocalQr $event.png_base64
        $script:qrDeadline = $clock.Elapsed.TotalSeconds + $remaining
        $event.png_base64 = ''; $message = $null
        Write-FileControlResult ([pscustomobject]@{event='operator_result';action='qr_start';result=@{displayed_locally=[FeibiQrWindow]::IsWindowVisible($script:qrForm.Handle);window_handle=$script:qrForm.Handle.ToInt64();expires_at_unix_ms=$event.expires_at_unix_ms}})
        Write-Host '{"event":"qr_displayed_locally"}'
      }
      elseif ($event.event -eq 'qr_closed') { Stop-LocalQr; Write-Host $message }
      elseif ($event.event -eq 'bounded_windows_stopped') {
        if (-not (Receive-StopReceipt $event)) { throw 'INVALID_STOP_RECEIPT' }
        $script:resultCode = $event.reason
        Write-Host ((@{event='bounded_windows_stopped';reason=$event.reason;children_exited=$event.children_exited;temporary_files_removed=$event.temporary_files_removed;account_authorization_revoked=$event.account_authorization_revoked} | ConvertTo-Json -Compress))
        break
      }
      elseif ($event.event -eq 'bounded_windows_started') {
        $script:startupStage = 'running'
        $script:confirmedDeadline = $event.deadline_utc
        $script:resultEvent = 'started'
        Write-StandaloneResult 'started'
        Write-Host $message
      }
      elseif (@('operator_result','operator_rejected','bounded_windows_health','bootstrap_rejected') -ccontains $event.event) { Write-FileControlResult $event; Write-Host $message }
      else { throw 'UNRECOGNIZED_SUPERVISOR_OUTPUT' }
      $script:pending = $script:process.StandardOutput.ReadLineAsync()
    }
    if ($NativeClipboard -or $StoredCredential) {
      $control = $null
      for ($count = 0; $count -lt 4 -and $script:controlInput.TryTake([ref]$control); $count++) {
        Assert-ControlInputOpen
        Send-Control $control
        $control = $null
      }
    } else { while ([Console]::KeyAvailable) {
      $key = [Console]::ReadKey($true)
      if ($key.Key -eq 'Enter') { Write-Host ''; Send-Control $line; $line = '' }
      elseif ($key.Key -eq 'Backspace') { if ($line.Length -gt 0) { $line = $line.Substring(0,$line.Length-1); [Console]::Write("`b `b") } }
      elseif ($key.KeyChar -match '[a-zA-Z ]' -and $line.Length -lt 20) { $line += $key.KeyChar; [Console]::Write($key.KeyChar) }
    } }
    [Windows.Forms.Application]::DoEvents()
    Start-Sleep -Milliseconds 50
  }
} catch {
  # No raw exceptions, entered text, proxy URLs, payloads or child log lines.
  $reason = 'CHECK_PREREQUISITES_OR_SAFE_STATUS'
  $allowed = @('LOCAL_CONTROL_UNAVAILABLE','LOCAL_CONTROL_TIMEOUT','LOCAL_CONTROL_BUSY','STORED_CREDENTIAL_MISSING','STORED_CREDENTIAL_DECRYPT_FAILED','STORED_CREDENTIAL_EXPIRED','STORED_CREDENTIAL_INVALID','STORED_CREDENTIAL_NOT_PRIVATE','STORED_CREDENTIAL_ALREADY_EXISTS','BRIDGE_ALREADY_RUNNING','STARTUP_VALIDATION_REQUIRES_RUN','NATIVE_STDIN_REQUIRES_RUN','NATIVE_STDIN_HOST_REQUIRED','NATIVE_CLIPBOARD_RETENTION_BLOCKED','CONTROL_PIPE_CLOSED','INPUT_BOUND_STOP','INVALID_OPERATOR_CONTROL','OPERATOR_STOP','INVALID_STOP_RECEIPT','PRIVATE_PIPE_WRITE_FAILED','TIME_LIMIT_REACHED','WINDOWS_X64_POWERSHELL_REQUIRED','ABSOLUTE_NODE_PATH_REQUIRED','PREFLIGHT_BLOCKED','EXPLICIT_ACTION_APPROVAL_REQUIRED','INVALID_RUN_PARAMETERS','INTERACTIVE_NATIVE_CONSOLE_REQUIRED','EXISTING_PROXY_REQUIRED','DIRECT_ROUTE_NOT_SUPPORTED','PROJECT_DIRECTORY_REQUIRED','NTFS_REQUIRED','REPARSE_DIRECTORY_REJECTED','PRIVATE_ACL_VERIFICATION_FAILED','WINDOWS_JOB_REQUIRED','WINDOWS_JOB_ASSIGNMENT_FAILED','SUPERVISOR_NOT_READY','KEY_PASTE_CHECK_FAILED','QR_DATA_REJECTED')
  if ($allowed -ccontains $_.Exception.Message) { $reason = $_.Exception.Message }
  $errorType = 'UNCLASSIFIED'
  $typeName = $_.Exception.GetType().FullName
  $allowedTypes = @('System.Management.Automation.CommandNotFoundException','System.Management.Automation.ParameterBindingException','System.Management.Automation.ParameterBindingValidationException','System.Management.Automation.MethodInvocationException','System.Management.Automation.PSInvalidCastException','System.Management.Automation.RuntimeException','System.ArgumentException','System.InvalidOperationException','System.UnauthorizedAccessException','System.Security.SecurityException','System.IO.IOException','System.IO.FileNotFoundException','System.TypeLoadException','System.ComponentModel.Win32Exception')
  if ($allowedTypes -ccontains $typeName) { $errorType = $typeName }
  $sourceLine = 0
  if ($null -ne $_.InvocationInfo) { $sourceLine = [Math]::Max(0,[int]$_.InvocationInfo.ScriptLineNumber) }
  $script:resultEvent = 'blocked'; $script:resultCode = $reason; $script:resultErrorType = $errorType
  if (@('OPERATOR_STOP','TIME_LIMIT_REACHED') -cnotcontains $reason) { $script:exitCode = 1 }
  Write-StandaloneResult 'blocked' $reason $errorType $script:exitCode
  Write-Host ((@{event='windows_launcher_blocked';reason=$reason;error_type=$errorType;source_line=$sourceLine} | ConvertTo-Json -Compress))
} finally {
  Stop-LocalQr
  if ($null -ne $script:controlInput) { $script:controlInput.Dispose(); $script:controlInput = $null }
  $script:runtimeKey = $null
  if ($script:bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($script:bstr) }
  if ($null -ne $script:secureKey) { $script:secureKey.Dispose() }
  if ($null -ne $script:process) {
    # Stop once, then drain the same outstanding stdout read for a bounded time.
    # Cleanup never displays or forwards QR records and does not extend activity.
    # A failed/pending write must not be followed by another write or a grace
    # period in which a late bootstrap could start work. Close the Job below.
    if (-not $script:pipeWriteFailed -and ($null -eq $script:writeOperation -or $script:writeOperation.IsCompleted)) { try {
      if (-not $script:process.HasExited -and -not $script:stopReceipt) {
        $stopBytes = [Text.Encoding]::UTF8.GetBytes('{"action":"stop"}' + "`n")
        $script:writeOperation = [FeibiPipeWrite]::Start($script:process.StandardInput.BaseStream,$stopBytes)
        if (-not $script:writeOperation.Wait(1000)) { throw 'PRIVATE_PIPE_WRITE_FAILED' }
        if (-not $script:writeOperation.Result) { throw 'PRIVATE_PIPE_WRITE_FAILED' }
        $script:writeOperation = $null
      }
      $finishWait = [Diagnostics.Stopwatch]::StartNew()
      $drainCount = 0
      while ($finishWait.Elapsed.TotalSeconds -lt 12 -and $drainCount -lt 128) {
        if ($null -eq $script:pending) { $script:pending = $script:process.StandardOutput.ReadLineAsync() }
        if ($script:pending.IsCompleted) {
          $finalLine = $script:pending.GetAwaiter().GetResult()
          $script:pending = $null
          if ($null -eq $finalLine) { break }
          $drainCount++
          try {
            if ($finalLine.Length -le 4096) { $finalEvent = $finalLine | ConvertFrom-Json; $null = Receive-StopReceipt $finalEvent }
          } catch { }
          $finalEvent = $null; $finalLine = $null
          if ($script:stopReceipt -and $script:process.HasExited) { break }
        } else {
          if ($script:process.HasExited -and $script:stopReceipt) { break }
          [Windows.Forms.Application]::DoEvents()
          Start-Sleep -Milliseconds 25
        }
      }
    } catch { } }
  }
  if ($script:job -ne [IntPtr]::Zero) { $script:jobClosed = [FeibiJob]::CloseHandle($script:job); $script:job = [IntPtr]::Zero }
  if ($null -ne $script:process) { if (-not $script:process.HasExited) { try { $script:process.Kill(); $null = $script:process.WaitForExit(5000) } catch { } }; $script:supervisorExited = $script:process.HasExited; $script:process.Dispose() }
  $removed = $true
  if ($null -ne $script:directory -and (Test-Path -LiteralPath $script:directory)) {
    # QR never persisted; remove only empty owned directories, not unknown files.
    try {
      foreach ($file in [IO.Directory]::GetFiles($script:directory,'operator-*')) {
        if ([IO.Path]::GetFileName($file) -cmatch '\Aoperator-(?:request\.json|[a-f0-9]{32}\.(?:json|tmp)|[a-f0-9]{32}\.json\.tmp)\z') { [IO.File]::Delete($file) }
      }
      $profiles = Join-Path $script:directory 'empty-profiles'
      if (Test-Path -LiteralPath $profiles) { [IO.Directory]::Delete($profiles,$false) }
      [IO.Directory]::Delete($script:directory,$false)
    } catch { }
    $removed = -not (Test-Path -LiteralPath $script:directory)
  }
  if ($StandaloneChild) {
    if ($script:resultEvent -ne 'blocked') { $script:resultEvent = 'stopped' }
    Write-StandaloneResult $script:resultEvent $script:resultCode $script:resultErrorType $script:exitCode
  }
  if ($null -ne $script:instanceMutex) {
    if ($script:instanceOwned) { $script:instanceMutex.ReleaseMutex() }
    $script:instanceMutex.Dispose()
  }
  if ($Run -and -not $Standalone) { Write-Host ((@{event='windows_launcher_cleanup';supervisor_receipt_observed=$script:stopReceipt;supervisor_cleanup_confirmed=$script:cleanupConfirmed;job_handle_closed=$script:jobClosed;supervisor_exited=$script:supervisorExited;temporary_files_removed=$removed;secure_memory_erasure_guaranteed=$false} | ConvertTo-Json -Compress)) }
}

if ($StandaloneChild -or $ControlCommand -ne '') { exit $script:exitCode }
