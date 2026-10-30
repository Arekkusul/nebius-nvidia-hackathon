"""Generate data/benign_corpus.jsonl: a realistic, seeded baseline of benign telemetry.

Every rule the agent writes is executed against this corpus. A rule that
fires here is "noisy" and goes back to the model with the offending events.

The corpus deliberately includes legitimate-but-suspicious-looking activity
(SCCM running encoded PowerShell, installers writing Run keys, admins using
whoami/net/schtasks, rundll32 launching real control-panel DLLs) because a
rule that cannot tell those apart is not deployable.

Run: python scripts/gen_benign_corpus.py
"""

from __future__ import annotations

import json
import random
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "benign_corpus.jsonl"
# Fixed seed: the corpus is checked in, and the recorded runs and eval numbers count benign
# hits against exactly these events, so a rebuild must reproduce the file byte for byte.
SEED = 1337

USERS = ["CORP\\jsmith", "CORP\\mchen", "CORP\\akumar", "CORP\\lgarcia", "CORP\\svc_backup", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\NETWORK SERVICE", "NT AUTHORITY\\LOCAL SERVICE", "CORP\\helpdesk01"]
HOSTS = ["WS-001.corp.local", "WS-042.corp.local", "LT-0137.corp.local", "SRV-FILE01.corp.local", "SRV-SCCM01.corp.local", "WS-188.corp.local", "LT-0201.corp.local"]
SYS32 = "C:\\Windows\\System32\\"
PF = "C:\\Program Files\\"
PF86 = "C:\\Program Files (x86)\\"


def _hashes(rng: random.Random) -> str:
    """Return a random digest in Sysmon's ``Hashes`` field format."""
    return f"SHA256={rng.getrandbits(256):064x}"


def _user(rng: random.Random, system_ok: bool = True) -> str:
    """Pick an account; ``system_ok=False`` limits it to interactive users."""
    pool = USERS if system_ok else [u for u in USERS if "AUTHORITY" not in u]
    return rng.choice(pool)


def base(rng: random.Random, category: str, product: str = "windows") -> dict:
    """Shared envelope fields. Underscored keys are metadata, not telemetry."""
    return {
        "_category": category,
        "_product": product,
        "Computer": rng.choice(HOSTS),
        "UtcTime": f"2026-10-{rng.randint(1, 28):02d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}.{rng.randint(0, 999):03d}",
    }


# The bulk of the corpus, because most Sigma rules target process_creation. Besides ordinary
# browser/Office/updater noise it deliberately carries the LOLBin usage a real estate shows:
# SCCM/Intune running -EncodedCommand PowerShell, admins running whoami/net/schtasks/sc/wmic/
# reg/nltest/systeminfo, rundll32 and regsvr32 loading real signed DLLs, mshta on a vendor HTA,
# certutil -hashfile/-urlfetch, bitsadmin /list, vssadmin/wbadmin listing, curl.exe fetching an
# install script. A rule keyed on the binary name or one flag alone fires here and is sent back.
def process_creation_events(rng: random.Random, n: int) -> list[dict]:
    """Windows Sysmon EventID 1 look-alikes."""
    # (Image, CommandLine template, ParentImage, Description/OriginalFileName)
    templates = [
        (SYS32 + "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s {svc}", SYS32 + "services.exe", "svchost.exe"),
        (SYS32 + "svchost.exe", "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p -s {svc}", SYS32 + "services.exe", "svchost.exe"),
        (PF + "Google\\Chrome\\Application\\chrome.exe", "\"{pf}Google\\Chrome\\Application\\chrome.exe\" --type=renderer --lang=en-US --field-trial-handle=1848 --mojo-platform-channel-handle=2904", PF + "Google\\Chrome\\Application\\chrome.exe", "chrome.exe"),
        (PF86 + "Microsoft\\Edge\\Application\\msedge.exe", "\"{pf86}Microsoft\\Edge\\Application\\msedge.exe\" --type=utility --utility-sub-type=network.mojom.NetworkService", PF86 + "Microsoft\\Edge\\Application\\msedge.exe", "msedge.exe"),
        (PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "\"{pf}Microsoft Office\\root\\Office16\\OUTLOOK.EXE\" ", SYS32 + "explorer.exe", "OUTLOOK.EXE"),
        (PF + "Microsoft Office\\root\\Office16\\EXCEL.EXE", "\"{pf}Microsoft Office\\root\\Office16\\EXCEL.EXE\" /dde", SYS32 + "explorer.exe", "EXCEL.EXE"),
        (PF + "Microsoft Office\\root\\Office16\\WINWORD.EXE", "\"{pf}Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\{u}\\Documents\\Q3-report.docx\"", SYS32 + "explorer.exe", "WINWORD.EXE"),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "\"C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe\" --type=renderer", "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "Teams.exe"),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "\"C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background", SYS32 + "explorer.exe", "OneDrive.exe"),
        (SYS32 + "conhost.exe", "\\??\\C:\\Windows\\system32\\conhost.exe 0x4", SYS32 + "cmd.exe", "conhost.exe"),
        (SYS32 + "cmd.exe", "C:\\Windows\\system32\\cmd.exe /c ipconfig /all", SYS32 + "cmd.exe", "cmd.exe"),
        (SYS32 + "cmd.exe", "cmd.exe /c dir \"C:\\Users\\{u}\\Downloads\" /b", SYS32 + "explorer.exe", "cmd.exe"),
        (SYS32 + "cmd.exe", "\"C:\\Windows\\system32\\cmd.exe\" /c \"C:\\scripts\\nightly-backup.cmd\"", SYS32 + "svchost.exe", "cmd.exe"),
        (SYS32 + "ipconfig.exe", "ipconfig /all", SYS32 + "cmd.exe", "ipconfig.exe"),
        (SYS32 + "ping.exe", "ping -n 4 srv-file01.corp.local", SYS32 + "cmd.exe", "ping.exe"),
        (SYS32 + "whoami.exe", "whoami /groups", SYS32 + "cmd.exe", "whoami.exe"),
        (SYS32 + "whoami.exe", "whoami", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "whoami.exe"),
        (SYS32 + "net.exe", "net use Z: \\\\srv-file01\\shares\\finance /persistent:yes", SYS32 + "cmd.exe", "net.exe"),
        (SYS32 + "net.exe", "net start spooler", SYS32 + "cmd.exe", "net.exe"),
        (SYS32 + "net1.exe", "C:\\Windows\\system32\\net1 use Z: \\\\srv-file01\\shares\\finance /persistent:yes", SYS32 + "net.exe", "net1.exe"),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\scripts\\inventory.ps1", SYS32 + "svchost.exe", "PowerShell.EXE"),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoLogo -NoProfile -Command \"Get-Service | Where-Object Status -eq 'Running'\"", SYS32 + "cmd.exe", "PowerShell.EXE"),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -Command \"Get-ChildItem C:\\Users\\{u}\\Documents -Recurse | Measure-Object\"", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "PowerShell.EXE"),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NonInteractive -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQAgAEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4ATQBhAG4AYQBnAGUAcgA7ACAARwBlAHQALQBDAE0ARABlAHYAaQBjAGUA", "C:\\Windows\\CCM\\CcmExec.exe", "PowerShell.EXE"),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\\Windows\\IMECache\\HealthScripts\\a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d_1\\detect.ps1", PF86 + "Microsoft Intune Management Extension\\Microsoft.Management.Services.IntuneWindowsAgent.exe", "PowerShell.EXE"),
        (PF + "PowerShell\\7\\pwsh.exe", "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\" -WorkingDirectory C:\\Users\\{u}\\repos\\app", PF + "Microsoft VS Code\\Code.exe", "pwsh.dll"),
        (SYS32 + "rundll32.exe", "rundll32.exe C:\\Windows\\system32\\shell32.dll,Control_RunDLL \"C:\\Windows\\system32\\inetcpl.cpl\"", SYS32 + "explorer.exe", "RUNDLL32.EXE"),
        (SYS32 + "rundll32.exe", "\"C:\\Windows\\system32\\rundll32.exe\" printui.dll,PrintUIEntry /in /n \"\\\\print01\\HP-3F\"", SYS32 + "explorer.exe", "RUNDLL32.EXE"),
        (SYS32 + "rundll32.exe", "C:\\Windows\\System32\\rundll32.exe C:\\Windows\\System32\\WerConCpl.dll,LaunchErcApp -queuereporting", SYS32 + "svchost.exe", "RUNDLL32.EXE"),
        (SYS32 + "rundll32.exe", "rundll32.exe C:\\Windows\\System32\\shell32.dll,OpenAs_RunDLL C:\\Users\\{u}\\Downloads\\notes.txt", SYS32 + "explorer.exe", "RUNDLL32.EXE"),
        (SYS32 + "regsvr32.exe", "regsvr32.exe /s C:\\Windows\\System32\\msxml6.dll", PF + "Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe", "REGSVR32.EXE"),
        (SYS32 + "regsvr32.exe", "\"C:\\Windows\\system32\\regsvr32.exe\" /s \"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\AcroIEFavClient.dll\"", SYS32 + "msiexec.exe", "REGSVR32.EXE"),
        (SYS32 + "schtasks.exe", "schtasks /query /fo LIST /v", SYS32 + "cmd.exe", "schtasks.exe"),
        (SYS32 + "schtasks.exe", "schtasks.exe /Create /TN \"GoogleUpdateTaskMachineUA\" /XML \"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdateTaskMachineUA.xml\" /F", PF86 + "Google\\Update\\GoogleUpdate.exe", "schtasks.exe"),
        (SYS32 + "schtasks.exe", "schtasks /Run /TN \"\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan\"", SYS32 + "cmd.exe", "schtasks.exe"),
        (SYS32 + "sc.exe", "sc query wuauserv", SYS32 + "cmd.exe", "sc.exe"),
        (SYS32 + "sc.exe", "sc config CcmExec start= delayed-auto", "C:\\Windows\\ccmsetup\\ccmsetup.exe", "sc.exe"),
        (SYS32 + "wbem\\WMIC.exe", "wmic os get Caption,Version /value", SYS32 + "cmd.exe", "wmic.exe"),
        (SYS32 + "wbem\\WMIC.exe", "wmic computersystem get domain", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "wmic.exe"),
        (SYS32 + "wbem\\WmiPrvSE.exe", "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding", SYS32 + "svchost.exe", "Wmiprvse.exe"),
        (SYS32 + "certutil.exe", "certutil -hashfile C:\\Users\\{u}\\Downloads\\installer.msi SHA256", SYS32 + "cmd.exe", "CertUtil.exe"),
        (SYS32 + "certutil.exe", "certutil -verify -urlfetch C:\\temp\\cert.cer", SYS32 + "cmd.exe", "CertUtil.exe"),
        (SYS32 + "msiexec.exe", "msiexec.exe /i \"C:\\Users\\{u}\\Downloads\\7z2401-x64.msi\" /qn", SYS32 + "explorer.exe", "msiexec.exe"),
        (SYS32 + "msiexec.exe", "C:\\Windows\\system32\\msiexec.exe /V", SYS32 + "services.exe", "msiexec.exe"),
        (SYS32 + "wscript.exe", "\"C:\\Windows\\System32\\wscript.exe\" \\\\corp.local\\netlogon\\mapdrives.vbs", SYS32 + "userinit.exe", "wscript.exe"),
        (SYS32 + "cscript.exe", "cscript //nologo C:\\Windows\\System32\\slmgr.vbs /xpr", SYS32 + "cmd.exe", "cscript.exe"),
        (SYS32 + "mshta.exe", "\"C:\\Windows\\System32\\mshta.exe\" \"C:\\Program Files (x86)\\HP\\HP Support Assistant\\Hpsa.hta\"", SYS32 + "explorer.exe", "MSHTA.EXE"),
        (SYS32 + "taskhostw.exe", "taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}", SYS32 + "svchost.exe", "taskhostw.exe"),
        (SYS32 + "dllhost.exe", "C:\\Windows\\system32\\DllHost.exe /Processid:{3EB3C877-1F16-487C-9050-104DBCD66683}", SYS32 + "svchost.exe", "dllhost.exe"),
        (SYS32 + "SearchProtocolHost.exe", "\"C:\\Windows\\system32\\SearchProtocolHost.exe\" Global\\UsGthrFltPipeMssGthrPipe12_ Global\\UsGthrCtrlFltPipeMssGthrPipe12 1 -2147483646", SYS32 + "SearchIndexer.exe", "SearchProtocolHost.exe"),
        (SYS32 + "backgroundTaskHost.exe", "\"C:\\Windows\\system32\\backgroundTaskHost.exe\" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca", SYS32 + "svchost.exe", "backgroundTaskHost.exe"),
        (PF86 + "Google\\Update\\GoogleUpdate.exe", "\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\" /svc", SYS32 + "services.exe", "GoogleUpdate.exe"),
        (PF86 + "Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe", "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /c", SYS32 + "svchost.exe", "MicrosoftEdgeUpdate.exe"),
        ("C:\\Windows\\CCM\\CcmExec.exe", "C:\\Windows\\CCM\\CcmExec.exe", SYS32 + "services.exe", "CcmExec.exe"),
        ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26090.3-0\\MsMpEng.exe", "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26090.3-0\\MsMpEng.exe\"", SYS32 + "services.exe", "MsMpEng.exe"),
        ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26090.3-0\\MpCmdRun.exe", "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26090.3-0\\MpCmdRun.exe\" -IdleTask -TaskName WdCacheMaintenance", SYS32 + "svchost.exe", "MpCmdRun.exe"),
        (PF + "Microsoft VS Code\\Code.exe", "\"C:\\Program Files\\Microsoft VS Code\\Code.exe\" --type=extensionHost", PF + "Microsoft VS Code\\Code.exe", "Code.exe"),
        (PF + "Git\\cmd\\git.exe", "git fetch origin main", PF + "Microsoft VS Code\\Code.exe", "git.exe"),
        (PF + "Git\\usr\\bin\\bash.exe", "C:\\Program Files\\Git\\usr\\bin\\bash.exe --login -i", PF + "Git\\git-bash.exe", "bash.exe"),
        (PF + "nodejs\\node.exe", "\"C:\\Program Files\\nodejs\\node.exe\" C:\\Users\\{u}\\repos\\app\\node_modules\\.bin\\vite --port 5173", PF + "Git\\usr\\bin\\bash.exe", "node.exe"),
        ("C:\\Users\\{u}\\AppData\\Local\\Programs\\Python\\Python312\\python.exe", "python.exe -m pip install --upgrade pip", SYS32 + "cmd.exe", "python.exe"),
        (SYS32 + "curl.exe", "curl.exe -sSL https://aka.ms/install-powershell.ps1 -o C:\\Users\\{u}\\Downloads\\install-powershell.ps1", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "curl.exe"),
        (SYS32 + "bitsadmin.exe", "bitsadmin /list /allusers", SYS32 + "cmd.exe", "bitsadmin.exe"),
        (SYS32 + "reg.exe", "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion /v ProductName", SYS32 + "cmd.exe", "reg.exe"),
        (SYS32 + "reg.exe", "reg add HKCU\\Software\\Microsoft\\Office\\16.0\\Outlook\\Options /v Foo /t REG_DWORD /d 1 /f", SYS32 + "cmd.exe", "reg.exe"),
        (SYS32 + "tasklist.exe", "tasklist /svc", SYS32 + "cmd.exe", "tasklist.exe"),
        (SYS32 + "systeminfo.exe", "systeminfo", SYS32 + "cmd.exe", "systeminfo.exe"),
        (SYS32 + "nltest.exe", "nltest /dsgetdc:corp.local", SYS32 + "cmd.exe", "nltestrk.exe"),
        (SYS32 + "gpupdate.exe", "gpupdate /force", SYS32 + "cmd.exe", "GPUpdate.exe"),
        (SYS32 + "wevtutil.exe", "wevtutil qe Security /c:5 /rd:true /f:text", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "wevtutil.exe"),
        (SYS32 + "vssadmin.exe", "vssadmin list shadows", SYS32 + "cmd.exe", "VSSADMIN.EXE"),
        (SYS32 + "wbadmin.exe", "wbadmin get versions", SYS32 + "cmd.exe", "WBADMIN.EXE"),
        (SYS32 + "lsass.exe", "C:\\Windows\\system32\\lsass.exe", SYS32 + "wininit.exe", "lsass.exe"),
        (SYS32 + "spoolsv.exe", "C:\\Windows\\System32\\spoolsv.exe", SYS32 + "services.exe", "spoolsv.exe"),
        (SYS32 + "RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding", SYS32 + "svchost.exe", "RuntimeBroker.exe"),
        (PF + "7-Zip\\7z.exe", "\"C:\\Program Files\\7-Zip\\7z.exe\" a -tzip C:\\Users\\{u}\\Documents\\archive.zip C:\\Users\\{u}\\Documents\\reports", SYS32 + "explorer.exe", "7z.exe"),
        (PF + "Zoom\\bin\\Zoom.exe", "\"C:\\Program Files\\Zoom\\bin\\Zoom.exe\" --url=zoommtg://zoom.us/join?action=join", PF + "Google\\Chrome\\Application\\chrome.exe", "Zoom.exe"),
        (PF86 + "Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe", "\"C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe\" \"C:\\Users\\{u}\\Downloads\\invoice-2211.pdf\"", PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "AcroRd32.exe"),
        (SYS32 + "cmd.exe", "\"cmd.exe\" /c echo %USERNAME% > C:\\Users\\{u}\\AppData\\Local\\Temp\\who.txt", PF + "Microsoft VS Code\\Code.exe", "cmd.exe"),
    ]
    svcs = ["wuauserv", "Schedule", "BITS", "EventLog", "Dnscache", "Winmgmt", "LanmanServer", "Themes", "UserManager"]
    out = []
    for _ in range(n):
        img, cmd, parent, orig = rng.choice(templates)
        u = _user(rng, system_ok=False).split("\\")[-1]
        evt = base(rng, "process_creation")
        evt.update(
            {
                "Image": img.replace("{u}", u),
                "CommandLine": cmd.replace("{u}", u).replace("{pf}", PF).replace("{pf86}", PF86).replace("{svc}", rng.choice(svcs)),
                "ParentImage": parent.replace("{u}", u),
                "OriginalFileName": orig,
                "User": "NT AUTHORITY\\SYSTEM" if parent.endswith("services.exe") or "CcmExec" in parent else f"CORP\\{u}",
                "IntegrityLevel": "System" if parent.endswith("services.exe") else rng.choice(["Medium", "High", "Medium"]),
                "ProcessId": rng.randint(400, 30000),
                "ParentProcessId": rng.randint(400, 30000),
                "Hashes": _hashes(rng),
                "CurrentDirectory": f"C:\\Users\\{u}\\" if "Users" in img else "C:\\Windows\\system32\\",
            }
        )
        out.append(evt)
    return out


# Stresses network_connection rules that key on the process alone: lsass talking LDAP/Kerberos
# to the DC, spoolsv to the print server over 445, powershell/curl reaching public hosts, SCCM on
# port 8530 and the usual browser/collaboration traffic.
def network_events(rng: random.Random, n: int) -> list[dict]:
    """Sysmon EventID 3: outbound connections from everyday software."""
    pairs = [
        (PF + "Google\\Chrome\\Application\\chrome.exe", ["www.google.com", "cdn.jsdelivr.net", "github.com", "outlook.office.com", "teams.microsoft.com", "stackoverflow.com"], 443),
        (PF86 + "Microsoft\\Edge\\Application\\msedge.exe", ["www.bing.com", "edge.microsoft.com", "www.microsoft.com"], 443),
        (SYS32 + "svchost.exe", ["update.microsoft.com", "download.windowsupdate.com", "login.microsoftonline.com", "settings-win.data.microsoft.com"], 443),
        (PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", ["outlook.office365.com", "autodiscover.corp.local"], 443),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", ["teams.microsoft.com", "statics.teams.cdn.office.net"], 443),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", ["oneclient.sfx.ms", "corp-my.sharepoint.com"], 443),
        ("C:\\Windows\\CCM\\CcmExec.exe", ["srv-sccm01.corp.local"], 8530),
        (PF + "Git\\mingw64\\bin\\git-remote-https.exe", ["github.com", "dev.azure.com"], 443),
        (SYS32 + "lsass.exe", ["dc01.corp.local"], 389),
        (SYS32 + "lsass.exe", ["dc01.corp.local"], 88),
        (SYS32 + "spoolsv.exe", ["print01.corp.local"], 445),
        ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26090.3-0\\MsMpEng.exe", ["wdcp.microsoft.com"], 443),
        (PF + "Zoom\\bin\\Zoom.exe", ["zoom.us"], 443),
        (PF + "Zoom\\bin\\Zoom.exe", ["zoomsjc.zoom.us"], 8801),
        (PF + "Slack\\app-4.41.105\\slack.exe", ["slack.com", "wss-primary.slack.com"], 443),
        (PF + "nodejs\\node.exe", ["registry.npmjs.org"], 443),
        ("C:\\Users\\{u}\\AppData\\Local\\Programs\\Python\\Python312\\python.exe", ["pypi.org", "files.pythonhosted.org"], 443),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", ["www.powershellgallery.com", "srv-sccm01.corp.local"], 443),
        (SYS32 + "curl.exe", ["aka.ms", "github.com"], 443),
    ]
    out = []
    for _ in range(n):
        img, hosts, port = rng.choice(pairs)
        u = _user(rng, system_ok=False).split("\\")[-1]
        host = rng.choice(hosts)
        evt = base(rng, "network_connection")
        evt.update(
            {
                "Image": img.replace("{u}", u),
                "User": "NT AUTHORITY\\SYSTEM" if ("svchost" in img or "lsass" in img or "spoolsv" in img or "CcmExec" in img or "MsMpEng" in img) else f"CORP\\{u}",
                "Protocol": "tcp",
                "Initiated": "true",
                "SourceIp": f"10.{rng.randint(10, 30)}.{rng.randint(0, 255)}.{rng.randint(2, 254)}",
                "SourcePort": rng.randint(49152, 65535),
                "DestinationIp": f"{rng.randint(13, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}" if "corp.local" not in host else f"10.0.0.{rng.randint(2, 50)}",
                "DestinationHostname": host,
                "DestinationPort": port,
                "DestinationIsIpv6": "false",
                "ProcessId": rng.randint(400, 30000),
            }
        )
        out.append(evt)
    return out


# Stresses persistence rules on registry_set: installers writing HKCU Run keys (OneDrive, Teams),
# services.exe changing a service Start value, DHCP rewriting DNS servers, PowerShell writing
# under HKCU. A rule that matches the key path without looking at the writer fires here.
def registry_events(rng: random.Random, n: int) -> list[dict]:
    """Sysmon EventID 13 (SetValue) from installers, updaters and Windows itself."""
    templates = [
        (PF86 + "Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe", "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\EdgeUpdate\\ClientState\\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}\\pv", "DWORD (0x00000001)"),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDriveSetup.exe", "HKU\\S-1-5-21-1004336348-1177238915-682003330-{rid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive", "\"C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\Update.exe", "HKU\\S-1-5-21-1004336348-1177238915-682003330-{rid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\com.squirrel.Teams.Teams", "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart \"Teams.exe\" --process-start-args \"--system-initiated\""),
        (SYS32 + "svchost.exe", "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{iface}\\DhcpNameServer", "10.0.0.2 10.0.0.3"),
        (SYS32 + "svchost.exe", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\LastOnlineScanTimeForAppCategory", "2026-10-{d} 03:00:00"),
        (SYS32 + "explorer.exe", "HKU\\S-1-5-21-1004336348-1177238915-682003330-{rid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\MRUListEx", "Binary Data"),
        (SYS32 + "msiexec.exe", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{B4C7A8E2-1A3F-4F6E-9D2C-5E8F1A2B3C4D}\\DisplayName", "7-Zip 24.01 (x64 edition)"),
        (PF + "Google\\Chrome\\Application\\chrome.exe", "HKU\\S-1-5-21-1004336348-1177238915-682003330-{rid}\\Software\\Google\\Chrome\\PreferenceMACs\\Default\\extensions.settings", "Binary Data"),
        ("C:\\Windows\\CCM\\CcmExec.exe", "HKLM\\SOFTWARE\\Microsoft\\CCM\\CcmEval\\LastEvalTime", "2026-10-{d} 09:12:44"),
        (SYS32 + "services.exe", "HKLM\\System\\CurrentControlSet\\Services\\BITS\\Start", "DWORD (0x00000002)"),
        (SYS32 + "poqexec.exe", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending", "DWORD (0x00000001)"),
        (PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "HKU\\S-1-5-21-1004336348-1177238915-682003330-{rid}\\Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\00000002\\Account Name", "{u}@corp.local"),
        (PF86 + "Google\\Update\\GoogleUpdate.exe", "HKLM\\SOFTWARE\\WOW6432Node\\Google\\Update\\LastChecked", "DWORD (0x6718a3c1)"),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "HKU\\S-1-5-21-1004336348-1177238915-682003330-{rid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\HideFileExt", "DWORD (0x00000000)"),
    ]
    out = []
    for _ in range(n):
        img, key, val = rng.choice(templates)
        u = _user(rng, system_ok=False).split("\\")[-1]
        rid = rng.randint(1000, 9999)
        evt = base(rng, "registry_set")
        evt.update(
            {
                "EventType": "SetValue",
                "Image": img.replace("{u}", u),
                "TargetObject": key.replace("{u}", u).replace("{rid}", str(rid)).replace("{iface}", "{" + f"{rng.getrandbits(128):032x}" + "}").replace("{d}", f"{rng.randint(1, 28):02d}"),
                "Details": val.replace("{u}", u).replace("{d}", f"{rng.randint(1, 28):02d}"),
                "User": "NT AUTHORITY\\SYSTEM" if "svchost" in img or "services.exe" in img or "CcmExec" in img or "poqexec" in img else f"CORP\\{u}",
                "ProcessId": rng.randint(400, 30000),
            }
        )
        out.append(evt)
    return out


# Stresses file_event rules on script/executable drops: PowerShell writing .ps1 files under Temp
# (its own policy-test file), updaters staging .exe in Temp, msiexec writing Program Files,
# browsers filling Downloads, Windows archiving the Security log.
def file_events(rng: random.Random, n: int) -> list[dict]:
    """Sysmon EventID 11: file creates by browsers, Office, updaters."""
    templates = [
        (PF + "Google\\Chrome\\Application\\chrome.exe", "C:\\Users\\{u}\\Downloads\\{name}.pdf"),
        (PF + "Google\\Chrome\\Application\\chrome.exe", "C:\\Users\\{u}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\Cache_Data\\f_{hex}"),
        (PF + "Microsoft Office\\root\\Office16\\WINWORD.EXE", "C:\\Users\\{u}\\Documents\\~${name}.docx"),
        (PF + "Microsoft Office\\root\\Office16\\EXCEL.EXE", "C:\\Users\\{u}\\AppData\\Local\\Temp\\{hex}.tmp"),
        (PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\{hex8}\\{name}.xlsx"),
        (SYS32 + "svchost.exe", "C:\\Windows\\SoftwareDistribution\\Download\\{hex}\\{hex}.cab"),
        (SYS32 + "svchost.exe", "C:\\Windows\\System32\\winevt\\Logs\\Archive-Security-2026-10-{d}.evtx"),
        ("C:\\Windows\\CCM\\CcmExec.exe", "C:\\Windows\\CCM\\Logs\\CcmExec.log"),
        ("C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26090.3-0\\MsMpEng.exe", "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory\\{hex8}"),
        (PF86 + "Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe", "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\Download\\{hex}\\MicrosoftEdge_X64_130.0.2849.56.exe"),
        (PF + "Microsoft VS Code\\Code.exe", "C:\\Users\\{u}\\repos\\app\\src\\{name}.ts"),
        (PF + "Git\\cmd\\git.exe", "C:\\Users\\{u}\\repos\\app\\.git\\index.lock"),
        (PF + "7-Zip\\7z.exe", "C:\\Users\\{u}\\Documents\\archive.zip"),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "C:\\ProgramData\\scripts\\inventory-{d}.csv"),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Users\\{u}\\AppData\\Local\\Temp\\__PSScriptPolicyTest_{hex8}.ps1"),
        (SYS32 + "msiexec.exe", "C:\\Windows\\Installer\\{hex}.msi"),
        (SYS32 + "msiexec.exe", "C:\\Program Files\\7-Zip\\7z.exe"),
        (PF86 + "Google\\Update\\GoogleUpdate.exe", "C:\\Program Files (x86)\\Google\\Temp\\GUM{hex8}.tmp\\GoogleUpdate.exe"),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "C:\\Users\\{u}\\OneDrive - Corp\\Documents\\{name}.pptx"),
        (PF + "Zoom\\bin\\Zoom.exe", "C:\\Users\\{u}\\Documents\\Zoom\\2026-10-{d} Weekly Sync\\zoom_0.mp4"),
    ]
    names = ["Q3-report", "budget-2027", "invoice-2211", "meeting-notes", "roadmap", "offer-letter", "slides", "main", "utils", "config"]
    out = []
    for _ in range(n):
        img, path = rng.choice(templates)
        u = _user(rng, system_ok=False).split("\\")[-1]
        evt = base(rng, "file_event")
        evt.update(
            {
                "Image": img.replace("{u}", u),
                "TargetFilename": path.replace("{u}", u).replace("{name}", rng.choice(names)).replace("{hex}", f"{rng.getrandbits(64):016x}").replace("{hex8}", f"{rng.getrandbits(32):08X}").replace("{d}", f"{rng.randint(1, 28):02d}"),
                "User": "NT AUTHORITY\\SYSTEM" if "svchost" in img or "CcmExec" in img or "MsMpEng" in img or "msiexec" in img else f"CORP\\{u}",
                "CreationUtcTime": evt["UtcTime"],
                "ProcessId": rng.randint(400, 30000),
            }
        )
        out.append(evt)
    return out


# Stresses dns_query rules keyed on the resolving process: powershell and curl resolving public
# hosts (gallery, GitHub, CDNs), lsass doing SRV lookups, plus everyday browser traffic.
def dns_events(rng: random.Random, n: int) -> list[dict]:
    """Sysmon EventID 22: everyday DNS lookups."""
    pairs = [
        (PF + "Google\\Chrome\\Application\\chrome.exe", ["www.google.com", "fonts.gstatic.com", "github.com", "www.youtube.com", "cdn.jsdelivr.net", "news.ycombinator.com", "corp.sharepoint.com", "api.github.com"]),
        (SYS32 + "svchost.exe", ["update.microsoft.com", "dns.msftncsi.com", "login.microsoftonline.com", "time.windows.com", "ctldl.windowsupdate.com", "wpad.corp.local"]),
        (PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", ["outlook.office365.com", "autodiscover-s.outlook.com", "corp.sharepoint.com"]),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", ["teams.microsoft.com", "presence.teams.microsoft.com"]),
        (SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", ["www.powershellgallery.com", "srv-sccm01.corp.local", "onegetcdn.azureedge.net"]),
        ("C:\\Windows\\CCM\\CcmExec.exe", ["srv-sccm01.corp.local"]),
        (PF + "nodejs\\node.exe", ["registry.npmjs.org"]),
        (SYS32 + "lsass.exe", ["dc01.corp.local", "_ldap._tcp.dc._msdcs.corp.local"]),
        (PF + "Slack\\app-4.41.105\\slack.exe", ["slack.com", "a.slack-edge.com"]),
        (SYS32 + "curl.exe", ["aka.ms", "github.com", "objects.githubusercontent.com"]),
    ]
    out = []
    for _ in range(n):
        img, hosts = rng.choice(pairs)
        u = _user(rng, system_ok=False).split("\\")[-1]
        evt = base(rng, "dns_query")
        evt.update(
            {
                "Image": img.replace("{u}", u),
                "QueryName": rng.choice(hosts),
                "QueryStatus": "0",
                "QueryResults": f"::ffff:{rng.randint(13, 220)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)};",
                "User": "NT AUTHORITY\\SYSTEM" if "svchost" in img or "lsass" in img or "CcmExec" in img else f"CORP\\{u}",
                "ProcessId": rng.randint(400, 30000),
            }
        )
        out.append(evt)
    return out


# Stresses image_load rules: wininet/winhttp/clr/samlib/vaultcli/dbghelp/amsi loading into PowerShell,
# Office and browsers, all signed by Microsoft. "DLL X loaded into process Y" rules need more than the
# DLL name to be deployable.
def image_load_events(rng: random.Random, n: int) -> list[dict]:
    """Sysmon EventID 7: signed Microsoft DLLs loading into normal processes."""
    dlls = ["ntdll.dll", "kernel32.dll", "advapi32.dll", "crypt32.dll", "wininet.dll", "winhttp.dll", "ole32.dll", "comctl32.dll", "mscoree.dll", "clr.dll", "System.Management.Automation.ni.dll", "vaultcli.dll", "samlib.dll", "dbghelp.dll", "wmiutils.dll", "taskschd.dll", "amsi.dll", "msxml6.dll", "shell32.dll", "urlmon.dll"]
    images = [PF + "Google\\Chrome\\Application\\chrome.exe", SYS32 + "svchost.exe", SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe", PF + "Microsoft Office\\root\\Office16\\OUTLOOK.EXE", SYS32 + "explorer.exe", SYS32 + "lsass.exe", SYS32 + "rundll32.exe", "C:\\Windows\\CCM\\CcmExec.exe", PF + "Microsoft VS Code\\Code.exe", SYS32 + "taskhostw.exe", SYS32 + "mmc.exe"]
    out = []
    for _ in range(n):
        dll = rng.choice(dlls)
        img = rng.choice(images)
        evt = base(rng, "image_load")
        evt.update(
            {
                "Image": img,
                "ImageLoaded": (SYS32 + dll) if not dll.endswith(".ni.dll") else "C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System.Manaa57fc8cc#\\" + f"{rng.getrandbits(128):032x}" + "\\" + dll,
                "Signed": "true",
                "Signature": "Microsoft Windows",
                "SignatureStatus": "Valid",
                "OriginalFileName": dll.replace(".ni.dll", ".dll"),
                "Company": "Microsoft Corporation",
                "Hashes": _hashes(rng),
                "User": _user(rng),
                "ProcessId": rng.randint(400, 30000),
            }
        )
        out.append(evt)
    return out


# Stresses ps_script (4104) rules keyed on cmdlet names: Get-Credential, Register-ScheduledTask,
# Invoke-WebRequest -OutFile, Add-Type, Get-ADComputer exports, Compress-Archive, Set-ItemProperty
# on HKCU, all from admin and SCCM scripts that run every day.
def ps_script_events(rng: random.Random, n: int) -> list[dict]:
    """PowerShell 4104 script blocks from admins, SCCM and modules."""
    blocks = [
        "Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName",
        "Import-Module ConfigurationManager; Get-CMDevice -Name $env:COMPUTERNAME",
        "$ErrorActionPreference = 'Stop'; Get-ChildItem -Path C:\\ProgramData\\scripts -Filter *.ps1 | ForEach-Object { . $_.FullName }",
        "Get-WmiObject -Class Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object DeviceID, FreeSpace, Size",
        "Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2/package/PSReadLine' -OutFile $env:TEMP\\psreadline.nupkg",
        "Register-ScheduledTask -TaskName 'Nightly Inventory' -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-File C:\\ProgramData\\scripts\\inventory.ps1') -Trigger (New-ScheduledTaskTrigger -Daily -At 2am)",
        "Get-EventLog -LogName System -Newest 50 | Where-Object { $_.EntryType -eq 'Error' }",
        "$cred = Get-Credential; Connect-ExchangeOnline -Credential $cred",
        "Test-NetConnection -ComputerName srv-file01.corp.local -Port 445",
        "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' -Name HideFileExt -Value 0",
        "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.MessageBox]::Show('Backup complete')",
        "Get-ADComputer -Filter * -Property OperatingSystem | Select-Object Name, OperatingSystem | Export-Csv C:\\ProgramData\\scripts\\computers.csv -NoTypeInformation",
        "Compress-Archive -Path C:\\ProgramData\\scripts\\*.csv -DestinationPath C:\\ProgramData\\scripts\\reports.zip -Force",
        "{ param($Path) Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum }",
    ]
    out = []
    for _ in range(n):
        u = _user(rng, system_ok=False).split("\\")[-1]
        evt = base(rng, "ps_script")
        evt.update(
            {
                "ScriptBlockText": rng.choice(blocks),
                "ScriptBlockId": f"{rng.getrandbits(128):032x}",
                "Path": rng.choice(["", "C:\\ProgramData\\scripts\\inventory.ps1", f"C:\\Users\\{u}\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1", "C:\\Windows\\CCM\\SystemTemp\\abc123.ps1"]),
                "User": f"CORP\\{u}",
                "EventID": 4104,
            }
        )
        out.append(evt)
    return out


# Stresses Linux process_creation rules: curl to the cloud metadata IP, curl/wget into /tmp,
# base64 -d, chmod +x, find -delete on logs, crontab -l, id/whoami, ss -tulpn, sudo, all from
# cron jobs, CI runners and routine admin sessions.
def linux_process_events(rng: random.Random, n: int) -> list[dict]:
    """Linux process creation from cron, CI runners and admins."""
    templates = [
        ("/usr/bin/bash", "/bin/bash /etc/cron.daily/logrotate", "/usr/sbin/cron", "root"),
        ("/usr/sbin/logrotate", "/usr/sbin/logrotate /etc/logrotate.conf", "/usr/bin/bash", "root"),
        ("/usr/bin/curl", "curl -fsSL https://deb.nodesource.com/setup_22.x -o /tmp/setup_22.sh", "/usr/bin/bash", "deploy"),
        ("/usr/bin/curl", "curl -s http://169.254.169.254/latest/meta-data/instance-id", "/usr/bin/bash", "ubuntu"),
        ("/usr/bin/wget", "wget -q https://github.com/cli/cli/releases/download/v2.60.0/gh_2.60.0_linux_amd64.deb -O /tmp/gh.deb", "/usr/bin/bash", "deploy"),
        ("/usr/bin/python3", "python3 -m venv /opt/app/.venv", "/usr/bin/bash", "app"),
        ("/usr/bin/python3", "/opt/app/.venv/bin/python -m gunicorn app:create_app() --bind 0.0.0.0:8000 --workers 4", "/usr/lib/systemd/systemd", "app"),
        ("/usr/bin/git", "git pull --ff-only origin main", "/usr/bin/bash", "deploy"),
        ("/usr/bin/docker", "docker compose up -d --remove-orphans", "/usr/bin/bash", "deploy"),
        ("/usr/bin/apt-get", "apt-get update", "/usr/bin/bash", "root"),
        ("/usr/bin/apt-get", "apt-get install -y unattended-upgrades", "/usr/bin/bash", "root"),
        ("/usr/bin/sudo", "sudo systemctl restart nginx", "/usr/bin/bash", "jsmith"),
        ("/usr/bin/systemctl", "systemctl restart nginx", "/usr/bin/sudo", "root"),
        ("/usr/bin/ssh", "ssh -o StrictHostKeyChecking=accept-new deploy@10.0.1.22 'uptime'", "/usr/bin/bash", "deploy"),
        ("/usr/bin/rsync", "rsync -az --delete /srv/www/ backup@10.0.1.40:/backups/www/", "/usr/bin/bash", "backup"),
        ("/usr/bin/tar", "tar -czf /backups/etc-2026-10-{d}.tgz /etc", "/usr/bin/bash", "root"),
        ("/usr/bin/find", "find /var/log -name '*.gz' -mtime +30 -delete", "/usr/bin/bash", "root"),
        ("/usr/bin/crontab", "crontab -l", "/usr/bin/bash", "jsmith"),
        ("/usr/bin/id", "id", "/usr/bin/bash", "jsmith"),
        ("/usr/bin/whoami", "whoami", "/usr/bin/bash", "ubuntu"),
        ("/usr/bin/cat", "cat /etc/os-release", "/usr/bin/bash", "ubuntu"),
        ("/usr/bin/ps", "ps aux --sort=-%mem", "/usr/bin/bash", "jsmith"),
        ("/usr/bin/ss", "ss -tulpn", "/usr/bin/sudo", "root"),
        ("/usr/bin/chmod", "chmod +x /opt/app/bin/entrypoint.sh", "/usr/bin/bash", "deploy"),
        ("/usr/bin/base64", "base64 -d /tmp/kubeconfig.b64", "/usr/bin/bash", "deploy"),
        ("/usr/bin/sh", "/bin/sh -c 'echo $(date) >> /var/log/healthcheck.log'", "/usr/sbin/cron", "root"),
        ("/usr/bin/kubectl", "kubectl get pods -n prod", "/usr/bin/bash", "deploy"),
        ("/usr/bin/aws", "aws s3 sync /srv/exports s3://corp-exports-prod/daily/", "/usr/bin/bash", "backup"),
        ("/usr/lib/apt/methods/https", "/usr/lib/apt/methods/https", "/usr/bin/apt-get", "_apt"),
        ("/usr/bin/sshd", "sshd: jsmith [priv]", "/usr/sbin/sshd", "root"),
    ]
    out = []
    for _ in range(n):
        img, cmd, parent, user = rng.choice(templates)
        evt = base(rng, "process_creation", product="linux")
        evt["Computer"] = rng.choice(["web-01.corp.internal", "web-02.corp.internal", "ci-runner-7.corp.internal", "db-01.corp.internal"])
        evt.update(
            {
                "Image": img,
                "CommandLine": cmd.replace("{d}", f"{rng.randint(1, 28):02d}"),
                "ParentImage": parent,
                "User": user,
                "CurrentDirectory": "/root" if user == "root" else f"/home/{user}",
                "ProcessId": rng.randint(300, 60000),
                "ParentProcessId": rng.randint(1, 60000),
            }
        )
        out.append(evt)
    return out


# Stresses cloudtrail rules keyed on eventName alone: GetSecretValue, kms Decrypt, ListUsers,
# DescribeTrails, AssumeRole, TerminateInstances and ConsoleLogin as Terraform, autoscaling, SDKs
# and the console produce them in normal operations.
def cloudtrail_events(rng: random.Random, n: int) -> list[dict]:
    """AWS CloudTrail management events from normal operations."""
    templates = [
        ("ec2.amazonaws.com", "DescribeInstances", "AssumedRole", "aws-cli/2.17.0", True),
        ("s3.amazonaws.com", "ListBuckets", "IAMUser", "console.amazonaws.com", True),
        ("sts.amazonaws.com", "GetCallerIdentity", "AssumedRole", "aws-sdk-go/1.44.0", True),
        ("sts.amazonaws.com", "AssumeRole", "AWSService", "ecs-tasks.amazonaws.com", False),
        ("iam.amazonaws.com", "ListUsers", "IAMUser", "console.amazonaws.com", True),
        ("iam.amazonaws.com", "GetRole", "AssumedRole", "terraform/1.9.5", True),
        ("lambda.amazonaws.com", "UpdateFunctionCode20150331v2", "AssumedRole", "terraform/1.9.5", False),
        ("ec2.amazonaws.com", "RunInstances", "AssumedRole", "terraform/1.9.5", False),
        ("ec2.amazonaws.com", "TerminateInstances", "AssumedRole", "autoscaling.amazonaws.com", False),
        ("cloudtrail.amazonaws.com", "DescribeTrails", "AssumedRole", "aws-cli/2.17.0", True),
        ("kms.amazonaws.com", "Decrypt", "AssumedRole", "aws-sdk-java/1.12.0", True),
        ("secretsmanager.amazonaws.com", "GetSecretValue", "AssumedRole", "aws-sdk-python/1.34.0", True),
        ("logs.amazonaws.com", "PutLogEvents", "AssumedRole", "aws-sdk-go/1.44.0", False),
        ("eks.amazonaws.com", "DescribeCluster", "AssumedRole", "kubectl/1.31", True),
        ("signin.amazonaws.com", "ConsoleLogin", "IAMUser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", False),
    ]
    out = []
    for _ in range(n):
        src, name, idtype, ua, ro = rng.choice(templates)
        evt = base(rng, "cloudtrail", product="aws")
        evt["_service"] = "cloudtrail"
        del evt["Computer"]
        evt.update(
            {
                "eventSource": src,
                "eventName": name,
                "eventType": "AwsApiCall" if name != "ConsoleLogin" else "AwsConsoleSignIn",
                "awsRegion": rng.choice(["us-east-1", "eu-west-1", "ap-southeast-1"]),
                "sourceIPAddress": f"203.0.113.{rng.randint(1, 254)}" if "amazonaws.com" not in ua else ua,
                "userAgent": ua,
                "readOnly": "true" if ro else "false",
                "userIdentity.type": idtype,
                "userIdentity.arn": f"arn:aws:iam::123456789012:user/{rng.choice(['jsmith', 'mchen', 'ci-deployer'])}" if idtype == "IAMUser" else f"arn:aws:sts::123456789012:assumed-role/{rng.choice(['TerraformDeploy', 'EcsTaskRole', 'ReadOnlyAuditor'])}/session",
                "errorCode": "",
                "recipientAccountId": "123456789012",
            }
        )
        out.append(evt)
    return out


def main() -> None:
    """Generate every event family with one seeded RNG and write the JSONL corpus."""
    rng = random.Random(SEED)
    events: list[dict] = []
    # Process creation dominates because it is by far the most common Sigma logsource. One RNG
    # consumed in this order means a family added at the end leaves earlier events unchanged.
    events += process_creation_events(rng, 1200)
    events += network_events(rng, 260)
    events += registry_events(rng, 160)
    events += file_events(rng, 160)
    events += dns_events(rng, 160)
    events += image_load_events(rng, 110)
    events += ps_script_events(rng, 70)
    events += linux_process_events(rng, 180)
    events += cloudtrail_events(rng, 90)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        for i, evt in enumerate(events):
            evt["_id"] = f"benign-{i:05d}"  # stable ids let a validation report cite the hit
            fh.write(json.dumps(evt, ensure_ascii=False) + "\n")
    print(f"wrote {len(events)} benign events to {OUT}")


if __name__ == "__main__":
    main()
