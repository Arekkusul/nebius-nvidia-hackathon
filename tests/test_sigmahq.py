"""SigmaHQ few-shot retrieval: deterministic, logsource-gated, technique-ranked."""

from __future__ import annotations

from rulesmith.models import LogSourceHint
from rulesmith.sigmahq import SigmaHQExamples

# A tiny in-memory corpus so the ranking tests do not depend on the shipped index.
RULES = [
    {"id": "1", "title": "Rundll32 Execution Of DLL From Temp", "status": "test", "logsource": {"product": "windows", "category": "process_creation"}, "tags": ["attack.defense-evasion", "attack.t1218.011"], "detection": {"selection": {"Image|endswith": "\\rundll32.exe", "CommandLine|contains": "\\Temp\\"}, "condition": "selection"}, "level": "medium"},
    {"id": "2", "title": "Regsvr32 Network Activity", "status": "stable", "logsource": {"product": "windows", "category": "network_connection"}, "tags": ["attack.defense-evasion", "attack.t1218.010"], "detection": {"selection": {"Image|endswith": "\\regsvr32.exe"}, "condition": "selection"}, "level": "high"},
    {"id": "3", "title": "Suspicious Process Masquerading As Svchost", "status": "test", "logsource": {"product": "windows", "category": "process_creation"}, "tags": ["attack.defense-evasion", "attack.t1036.005"], "detection": {"selection": {"Image|endswith": "\\svchost.exe"}, "condition": "selection"}, "level": "high"},
    {"id": "4", "title": "Kerberos RC4 Ticket Request", "status": "test", "logsource": {"product": "windows", "service": "security", "definition": "needs auditing"}, "tags": ["attack.credential-access", "attack.t1558.003"], "detection": {"selection": {"EventID": 4769, "TicketEncryptionType": "0x17"}, "condition": "selection"}, "level": "medium"},
    {"id": "5", "title": "Linux Rundll32 Lookalike", "status": "test", "logsource": {"product": "linux", "category": "process_creation"}, "tags": ["attack.t1218.011"], "detection": {"selection": {"Image|endswith": "/rundll32"}, "condition": "selection"}, "level": "low"},
]


def test_find_requires_same_logsource_and_ranks_by_technique():
    ex = SigmaHQExamples(RULES)
    hits = ex.find(LogSourceHint(category="process_creation", product="windows", service="sysmon"), ["T1218.011"], "Rundll32 Loads DLL From AppData", k=3)
    titles = [h["title"] for h in hits]
    # The exact sub-technique match comes first; the Linux rule with the same tag is a different product and is excluded.
    assert titles[0] == "Rundll32 Execution Of DLL From Temp"
    assert "Linux Rundll32 Lookalike" not in titles
    assert "Regsvr32 Network Activity" not in titles, "different category must not leak in"


def test_find_matches_category_less_logsources_by_service_and_parent_technique():
    ex = SigmaHQExamples(RULES)
    hits = ex.find(LogSourceHint(category="", product="windows", service="security"), ["T1558"], "Kerberoasting burst", k=2)
    assert [h["title"] for h in hits] == ["Kerberos RC4 Ticket Request"]


def test_find_returns_nothing_for_unknown_logsource_or_no_overlap():
    ex = SigmaHQExamples(RULES)
    assert ex.find(LogSourceHint(category="process_creation", product="macos", service=""), ["T1218.011"], "x") == []
    assert ex.find(LogSourceHint(category="process_creation", product="windows", service=""), ["T9999"], "zzz") == []


def test_render_is_prompt_ready_yaml_and_drops_logsource_definition():
    text = SigmaHQExamples.render(SigmaHQExamples(RULES).find(LogSourceHint(category="", product="windows", service="security"), ["T1558.003"], "", k=1))
    assert text.startswith("REFERENCE RULES FROM SIGMAHQ")
    assert "TicketEncryptionType: '0x17'" in text or "TicketEncryptionType: 0x17" in text
    assert "definition" not in text
    assert SigmaHQExamples.render([]) == ""


def test_shipped_index_loads_and_covers_the_core_logsources():
    ex = SigmaHQExamples()
    assert len(ex) > 2500
    for ls, tid, title in [
        (LogSourceHint(category="process_creation", product="windows", service="sysmon"), "T1003.001", ""),
        # SigmaHQ has no T1530-tagged CloudTrail rule, so this one must come from the title words.
        (LogSourceHint(category="", product="aws", service="cloudtrail"), "T1530", "S3 Bucket Policy Modified For Public Read Access"),
        (LogSourceHint(category="process_creation", product="linux", service=""), "T1053.003", ""),
    ]:
        hits = ex.find(ls, [tid], title, k=3)
        assert hits, f"no SigmaHQ example for {ls} {tid}"
        assert all((h["logsource"].get("product") or "").lower() == ls.product for h in hits)
