# -*- coding: utf-8 -*-
"""Extra PowerShell queries (raw strings = exactly what PowerShell receives)."""
NEW_Q = {
 "av2": r"""Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | foreach { $p=$_.pathToSignedProductExe; $ex=[bool]($p -and (Test-Path $p -ErrorAction SilentlyContinue)); $st=''; $sg=''; if($ex){ $s=Get-AuthenticodeSignature $p; $st=[string]$s.Status; $sg=[string]$s.SignerCertificate.Subject }; [pscustomobject]@{Name=$_.displayName;Path=$p;Exists=$ex;Status=$st;Signer=$sg} }""",
 "kmsfiles": r"""@('C:\Windows\AutoKMS','C:\Program Files\KMSpico','C:\Windows\KMSAutoS','C:\Windows\System32\SppExtComObjHook.dll','C:\Windows\System32\SppExtComObjPatcher.dll','C:\Windows\SECOH-QAD.exe','C:\Windows\KMS-QADhook','C:\ProgramData\KMSAutoS','C:\Program Files\KMSAuto Net','C:\Windows\System32\Tasks\AutoPico') | where { Test-Path $_ }""",
 "kmstasks": r"""Get-ScheduledTask | where { $_.TaskName -match 'KMS|AutoPico|Activat(or|ion)Task|Re-?Loader' } | select -ExpandProperty TaskName""",
 "procpaths": r"""Get-Process -Name svchost,lsass,csrss,winlogon,services,smss,wininit,explorer,taskhostw,dwm,spoolsv,lsm -ErrorAction SilentlyContinue | select Name,Path -Unique""",
 "procnames": r"""Get-Process | select -ExpandProperty Name -Unique""",
 "sigs": r"""Get-Process -ErrorAction SilentlyContinue | where { $_.Path -and $_.Path -notlike 'C:\Windows\*' } | select -ExpandProperty Path -Unique | select -First 90 | foreach { $s=Get-AuthenticodeSignature $_ -ErrorAction SilentlyContinue; [pscustomobject]@{Path=$_;Status=[string]$s.Status;Signer=[string]$s.SignerCertificate.Subject} }""",
 "whea": r"""@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger';StartTime=(Get-Date).AddDays(-30)} -MaxEvents 50 -ErrorAction SilentlyContinue).Count""",
 "diskerr": r"""@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='disk','Ntfs','volmgr','stornvme','storahci';Level=1,2;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 200 -ErrorAction SilentlyContinue).Count""",
 "throttle": r"""@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Processor-Power';Id=37;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 200 -ErrorAction SilentlyContinue).Count""",
 "crashes": r"""Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 300 -ErrorAction SilentlyContinue | foreach { $_.Properties[0].Value } | group | sort Count -desc | select -First 6 Name,Count""",
 "minidumps": r"""@(Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue).Count""",
 "memdiag": r"""Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'} -MaxEvents 2 -ErrorAction SilentlyContinue | select @{n='T';e={"{0:yyyy-MM-dd}" -f $_.TimeCreated}},Message""",
 "wmipersist": r"""Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | where { $_.Name -ne 'SCM Event Log Consumer' } | select Name,@{n='Class';e={$_.CimClass.CimClassName}}""",
 "localadmins": r"""Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | select Name,ObjectClass,PrincipalSource""",
 "bits": r"""Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | select DisplayName,JobState,@{n='Url';e={($_.FileList | select -First 1).RemoteName}}""",
 "newest_evt": r"""Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction SilentlyContinue | select @{n='T';e={"{0:yyyy-MM-dd HH:mm}" -f $_.TimeCreated}}""",
}
