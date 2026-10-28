param([ValidateSet('Protect','Unprotect')][string]$Mode)
$ErrorActionPreference='Stop'
try {
 Add-Type -AssemblyName System.Security
 $b=[Convert]::FromBase64String([Console]::In.ReadToEnd())
 if($Mode -eq 'Protect'){$r=[Security.Cryptography.ProtectedData]::Protect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)}
 else{$r=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)}
 [Console]::Out.Write([Convert]::ToBase64String($r))
 [Array]::Clear($b,0,$b.Length);[Array]::Clear($r,0,$r.Length)
}catch{[Console]::Error.Write('STATE_DPAPI_FAILED');exit 1}
