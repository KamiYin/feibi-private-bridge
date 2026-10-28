param([switch]$Resume,[string]$StateDirectory='')
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$state=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'FeibiPrivateBridge\credentials'
if ($StateDirectory -ne '') { $state=[IO.Path]::GetFullPath($StateDirectory) }
$configuration=Get-Content -Raw -LiteralPath (Join-Path $root 'deployment.local.json') | ConvertFrom-Json
if($configuration.tunnel_id -notmatch '^tunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}$' -or $configuration.owner_nonce -notmatch '^bind:[A-Za-z0-9_-]{16,80}$'){throw 'INVALID_DEPLOYMENT_CONFIGURATION'}
$marker=Join-Path $state 'operator-stopped'
if($Resume -and [IO.File]::Exists($marker)){[IO.File]::Delete($marker)}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$mutex=New-Object Threading.Mutex($false,('Local\FeibiPrivateBridge-continuous-'+$sid));$owned=$false
try {
 try{$owned=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$owned=$true}
 if(-not $owned){exit 0}
 while(-not [IO.File]::Exists($marker)){
  $hostPath=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $argsText='-NoLogo -NoProfile -STA -ExecutionPolicy RemoteSigned -File "'+(Join-Path $root 'start.ps1')+'" -Run -StandaloneChild -Persistent -StoredCredential -ApprovePrivateTunnel -ApproveQrLogin -ApproveOwnerTextTransfer -ApproveOwnerReply -TunnelId '+$configuration.tunnel_id+' -OwnerNonce '+$configuration.owner_nonce
  $info=New-Object Diagnostics.ProcessStartInfo
  $info.FileName=$hostPath;$info.Arguments=$argsText;$info.WorkingDirectory=$root
  $info.UseShellExecute=$false;$info.CreateNoWindow=$true
  $child=[Diagnostics.Process]::Start($info)
  $child.WaitForExit();$child.Dispose()
  $receipt=Get-Content -Raw -LiteralPath (Join-Path $root 'standalone-result.json')|ConvertFrom-Json
  if($receipt.code -eq 'OPERATOR_STOP'){[IO.File]::WriteAllText($marker,'stopped');break}
  if($receipt.code -in @('STORED_CREDENTIAL_EXPIRED','STORED_CREDENTIAL_MISSING','STORED_CREDENTIAL_DECRYPT_FAILED')){break}
  Start-Sleep -Seconds 5
 }
}finally{if($owned){$mutex.ReleaseMutex()};$mutex.Dispose()}
