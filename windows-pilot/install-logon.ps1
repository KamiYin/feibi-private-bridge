# Explicit installation only. Run after coordinating the production cutover.
$ErrorActionPreference='Stop'
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$hostPath=Join-Path $env:SystemRoot 'System32\wscript.exe'
$action=New-ScheduledTaskAction -Execute $hostPath -Argument ('//B //NoLogo "'+(Join-Path $PSScriptRoot 'launch-hidden.vbs')+'"') -WorkingDirectory $PSScriptRoot
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $user
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$null=Register-ScheduledTask -TaskName 'FeibiPrivateBridge' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
'LOGON_TASK_REGISTERED'
