Option Explicit
Dim shell, fso, root, host, command, result
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
host = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
command = Chr(34) & host & Chr(34) & " -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File " & Chr(34) & root & "\continuous.ps1" & Chr(34)
result = shell.Run(command, 0, True)
WScript.Quit result
