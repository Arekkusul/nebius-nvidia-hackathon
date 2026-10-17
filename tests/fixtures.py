"""Canned model outputs shared by pipeline, server and CLI tests."""

from __future__ import annotations

from rulesmith.models import (
    DetectionCandidate,
    DetectionPlan,
    LogSourceHint,
    RedTeamVariants,
    RefinedRule,
    RuleDraft,
    TestEvent,
    ThreatReport,
)

REPORT_TEXT = (
    "# Example intrusion report\n\n"
    "The operators gained initial access through a phishing email carrying a macro-enabled Word document. "
    "When opened, WINWORD.EXE spawned PowerShell with an encoded command that downloaded the loader. "
    "The loader established persistence by writing a Run key named 'OneDriveUpd' under HKCU pointing to a DLL in %APPDATA%. "
    "Later, rundll32.exe was used to execute the DLL from the AppData folder. The C2 domain was updates-cdn[.]example."
) * 2

THREAT_REPORT = ThreatReport(
    title="Macro-to-PowerShell loader campaign",
    summary="Phishing document spawns encoded PowerShell, persists via Run key, executes DLL with rundll32.",
    threat_actors=["TA-EXAMPLE"],
    malware_families=["ExampleLoader"],
    targets=["Finance"],
    behaviors=[
        {
            "id": "B1",
            "description": "Office application spawns PowerShell with an encoded command.",
            "attack_technique_id": "T1059.001",
            "attack_tactic": "Execution",
            "observables": [{"kind": "parent_process", "value": "WINWORD.EXE"}, {"kind": "command_line", "value": "-enc"}],
            "logsource": {"category": "process_creation", "product": "windows"},
            "evidence": "WINWORD.EXE spawned PowerShell with an encoded command that downloaded the loader.",
            "confidence": 0.95,
            "detectable": True,
        },
        {
            "id": "B2",
            "description": "Run key persistence pointing to a DLL in AppData.",
            "attack_technique_id": "T1547.001",
            "attack_tactic": "Persistence",
            "observables": [{"kind": "registry_key", "value": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpd"}],
            "logsource": {"category": "registry_set", "product": "windows"},
            "evidence": "writing a Run key named 'OneDriveUpd' under HKCU pointing to a DLL in %APPDATA%",
            "confidence": 0.9,
            "detectable": True,
        },
        {
            "id": "B3",
            "description": "C2 domain contact.",
            "attack_technique_id": "T1071.001",
            "attack_tactic": "Command and Control",
            "observables": [{"kind": "network_domain", "value": "updates-cdn.example"}],
            "logsource": {"category": "dns_query", "product": "windows"},
            "evidence": "The C2 domain was updates-cdn[.]example.",
            "confidence": 0.8,
            "detectable": False,
        },
    ],
    iocs=[{"type": "domain", "value": "updates-cdn.example"}],
)

PLAN = DetectionPlan(
    candidates=[
        DetectionCandidate(
            id="D1",
            title="Office Application Spawning Encoded PowerShell",
            behavior_ids=["B1"],
            attack_technique_ids=["T1059.001"],
            logsource=LogSourceHint(category="process_creation", product="windows"),
            rationale="Macro launching encoded PowerShell is the initial execution step.",
            key_fields=["ParentImage", "Image", "CommandLine"],
            false_positive_risks="Admins launching encoded PowerShell from cmd; exclude by requiring an Office parent.",
            priority="high",
        )
    ],
    skipped=["B3: domain IOC only"],
    notes="Focus on the execution chain.",
)

GOOD_YAML = """
title: Office Application Spawning Encoded PowerShell
status: experimental
description: Detects Office spawning PowerShell with an encoded command.
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
  selection_child:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - '-e '
      - '-ec '
  condition: selection_parent and selection_child
falsepositives:
  - Unlikely
level: high
"""

# Too broad: no parent constraint, so it fires on SCCM encoded PowerShell in the benign corpus.
BROAD_YAML = GOOD_YAML.replace("condition: selection_parent and selection_child", "condition: selection_child")

TESTS = [
    TestEvent(id="P1", label="positive", description="Word spawns encoded PS", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA"}),
    TestEvent(id="P2", label="positive", description="Excel spawns pwsh", event={"Image": "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "CommandLine": "pwsh -EncodedCommand AAAA"}),
    TestEvent(id="P3", label="positive", description="Word spawns PS, mixed case", event={"Image": "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\winword.exe", "CommandLine": "POWERSHELL -ENC QQBB"}),
    TestEvent(id="N1", label="negative", description="Admin encoded PS from cmd", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "powershell.exe -enc SQBFAFgA"}),
    TestEvent(id="N2", label="negative", description="Word spawns plain PS", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell.exe -File C:\\scripts\\ok.ps1"}),
    TestEvent(id="N3", label="negative", description="Word opens doc", event={"Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "ParentImage": "C:\\Windows\\explorer.exe", "CommandLine": "WINWORD.EXE /n report.docx"}),
]

GOOD_DRAFT = RuleDraft(candidate_id="D1", sigma_yaml=GOOD_YAML, tests=TESTS, author_notes="Parent constraint keeps it quiet.")
BROAD_DRAFT = RuleDraft(candidate_id="D1", sigma_yaml=BROAD_YAML, tests=TESTS, author_notes="first attempt")
REFINED_GOOD = RefinedRule(sigma_yaml=GOOD_YAML, change_summary="Required an Office parent process.", additional_tests=[])

REDTEAM = RedTeamVariants(
    variants=[
        TestEvent(id="X", label="positive", description="-ec abbreviation", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell -ec QQBB"}),
        TestEvent(id="X", label="positive", description="quoted path, reordered", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -w hidden -EncodedCommand QQBB -nop"}),
    ],
    analysis="Flag aliases are covered; renamed binaries would need OriginalFileName.",
)


def responses_all_good():
    """Scripted responses where the first draft already passes."""
    return {"extract": THREAT_REPORT, "plan": PLAN, "author": GOOD_DRAFT, "redteam": REDTEAM}


def responses_refine_once():
    """First draft too broad (fires on SCCM encoded PowerShell), refine fixes it."""
    return {"extract": THREAT_REPORT, "plan": PLAN, "author": BROAD_DRAFT, "refine": [REFINED_GOOD], "redteam": REDTEAM}
