"""Tests for the deterministic validation engine."""

from __future__ import annotations

from rulesmith.models import RuleDraft, TestEvent
from rulesmith.validate import AttackIndex, BenignCorpus, RuleRunner, check_rule, compile_rule, validate_rule
from rulesmith.validate.fields import FieldDictionary

GOOD_RULE = """
title: Encoded PowerShell Launched By Office Application
id: 0f4b1c3e-5a1d-4c33-9b0e-7a1d2e3f4a5b
status: experimental
description: Detects Office spawning PowerShell with an encoded command, a classic macro-to-payload chain.
references:
  - https://example.invalid/report
author: RuleSmith
date: 2026-10-17
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1566.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
      - '\\OUTLOOK.EXE'
  selection_child:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
      - '-e '
  condition: selection_parent and selection_child
falsepositives:
  - Unlikely
level: high
"""

POS = TestEvent(id="P1", label="positive", description="Word spawns encoded PS", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA"})
POS2 = TestEvent(id="P2", label="positive", description="Excel spawns pwsh, mixed case", event={"Image": "C:\\Program Files\\PowerShell\\7\\PWSH.EXE", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\excel.exe", "CommandLine": "pwsh -EncodedCommand AAAA"})
NEG = TestEvent(id="N1", label="negative", description="Admin runs encoded PS from cmd", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "powershell.exe -enc SQBFAFgA"})
NEG2 = TestEvent(id="N2", label="negative", description="Word spawns plain PS", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell.exe -File C:\\scripts\\ok.ps1"})


def test_check_rule_parses_good_rule_without_errors():
    rule, issues = check_rule(GOOD_RULE, expected_techniques=["T1059.001"])
    assert rule is not None
    assert not [i for i in issues if i.severity == "error"], issues


def test_check_rule_flags_yaml_and_missing_keys():
    rule, issues = check_rule("title: [unclosed")
    assert rule is None and issues[0].code == "yaml_invalid"
    rule, issues = check_rule("title: x\nlogsource:\n  category: process_creation\n")
    assert rule is None and any(i.code == "missing_key" for i in issues)


def test_check_rule_flags_unknown_field_and_bad_attack_id():
    bad = GOOD_RULE.replace("CommandLine|contains", "CommandLineArgs|contains").replace("attack.t1566.001", "attack.t9999.999")
    rule, issues = check_rule(bad)
    assert rule is not None
    codes = {i.code: i.severity for i in issues}
    assert codes.get("unknown_field") == "error"
    assert codes.get("attack_id_unknown") == "error"


def test_check_rule_flags_over_broad_and_wildcard():
    broad = """
title: PowerShell Started
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\powershell.exe'
  condition: sel
level: low
"""
    _rule, issues = check_rule(broad)
    assert any(i.code == "over_broad" and i.severity == "error" for i in issues)
    wild = broad.replace("Image|endswith: '\\powershell.exe'", "CommandLine: '*'")
    _rule, issues = check_rule(wild)
    assert any(i.code == "wildcard_only" for i in issues)


def test_check_rule_unknown_logsource_is_info_not_error():
    rule, issues = check_rule(GOOD_RULE.replace("product: windows", "product: zos").replace("category: process_creation", "category: mainframe_jobs"))
    assert rule is not None
    assert any(i.code == "logsource_unknown" for i in issues)
    assert not [i for i in issues if i.severity == "error"]


def test_compile_and_run_tests():
    rule, _ = check_rule(GOOD_RULE)
    sql = compile_rule(rule)
    assert "ParentImage" in sql and "LIKE" in sql
    runner = RuleRunner(sql)
    outcomes = {o.event_id: o for o in runner.run_tests([POS, POS2, NEG, NEG2])}
    assert outcomes["P1"].matched and outcomes["P1"].passed
    assert outcomes["P2"].matched, "matching must be case-insensitive"
    assert not outcomes["N1"].matched and outcomes["N1"].passed
    assert not outcomes["N2"].matched and outcomes["N2"].passed


def test_runner_tolerates_missing_columns_and_regex():
    rule, _ = check_rule(GOOD_RULE.replace("CommandLine|contains:\n      - '-enc'\n      - '-EncodedCommand'\n      - '-e '", "CommandLine|re: '-e(nc|ncodedcommand)?\\s'"))
    sql = compile_rule(rule)
    runner = RuleRunner(sql)
    # event without CommandLine key at all must not crash and must not match
    evt = TestEvent(id="X", label="negative", description="", event={"Image": "C:\\x\\powershell.exe"})
    out = runner.run_tests([evt, POS])
    assert [o.matched for o in out] == [False, True]


def test_validate_rule_passes_with_good_tests_and_quiet_corpus():
    corpus = BenignCorpus()
    assert len(corpus) > 2000
    draft = RuleDraft(candidate_id="D1", sigma_yaml=GOOD_RULE, tests=[POS, POS2, NEG, NEG2])
    report = validate_rule(draft, corpus=corpus, expected_techniques=["T1059.001"])
    assert report.parse_ok
    assert report.passed, report.issues
    assert report.positives_matched == 2 and report.negatives_matched == 0
    assert report.benign_total > 1000 and report.benign_hits == 0


def test_validate_rule_fails_on_benign_noise_with_examples():
    noisy = GOOD_RULE.replace("condition: selection_parent and selection_child", "condition: selection_child")
    draft = RuleDraft(candidate_id="D1", sigma_yaml=noisy, tests=[POS, NEG2])
    report = validate_rule(draft, corpus=BenignCorpus())
    assert not report.passed
    assert report.benign_hits >= 1, "SCCM/Intune encoded PowerShell in the corpus should trip a naive -enc rule"
    assert report.benign_examples and "CommandLine" in report.benign_examples[0]
    assert any(i.code == "benign_noise" for i in report.issues)
    assert "benign" in report.summary()


def test_validate_rule_reports_missed_positive_and_matched_negative():
    draft = RuleDraft(candidate_id="D1", sigma_yaml=GOOD_RULE, tests=[POS, TestEvent(id="P9", label="positive", description="not actually covered", event={"Image": "C:\\x\\notepad.exe", "ParentImage": "C:\\x\\WINWORD.EXE", "CommandLine": "notepad"}), TestEvent(id="N9", label="negative", description="mislabelled", event=POS.event)])
    report = validate_rule(draft, corpus=None)
    codes = [i.code for i in report.issues]
    assert "positive_missed" in codes and "negative_matched" in codes
    assert not report.passed


def test_validate_rule_requires_positive_tests():
    report = validate_rule(RuleDraft(candidate_id="D1", sigma_yaml=GOOD_RULE, tests=[NEG]), corpus=None)
    assert any(i.code == "no_positive_tests" for i in report.issues) and not report.passed


def test_attack_index_lookup():
    idx = AttackIndex()
    assert idx.exists("t1059.001") and idx.name("T1059.001") == "PowerShell"
    assert idx.parent("T1059.001") == "T1059"
    assert not idx.exists("T9999")
    assert idx.is_valid_format("T1234.001") and not idx.is_valid_format("TA0001")


def test_field_dictionary_prefix_and_strictness():
    fd = FieldDictionary()
    allowed = fd.known_fields(None, "aws", "cloudtrail")
    assert fd.check("requestParameters.bucketName", allowed)
    assert fd.check("eventname", allowed)
    assert not fd.check("bogusField", allowed)
    assert fd.is_strict("process_creation") and not fd.is_strict("cloudtrail")
    assert fd.known_fields("mystery", "windows", None) is None, "unknown category: skip field checks rather than guess"
    assert fd.known_fields("mystery", "zos", None) is None


def test_corpus_filtering_by_logsource():
    corpus = BenignCorpus()
    assert len(corpus.events_for(category="process_creation", product="windows")) > 1000
    assert len(corpus.events_for(category="process_creation", product="linux")) > 100
    assert len(corpus.events_for(category="registry_event", product="windows")) > 100
    assert len(corpus.events_for(category=None, product="aws", service="cloudtrail")) > 50
    assert corpus.events_for(category="process_creation", product="macos") == []
    assert "_id" not in corpus.strip_meta(corpus.events[0])


def test_runner_merges_case_colliding_keys():
    """Events whose keys differ only in case must share one SQLite column and still match."""
    from rulesmith.validate import RuleRunner, check_rule, compile_rule

    rule, _ = check_rule(GOOD_RULE)
    runner = RuleRunner(compile_rule(rule))
    lower = {k.lower(): v for k, v in POS.event.items()}  # same event, lower-cased keys
    hits = runner.match_indices([POS.event, lower, NEG.event])
    assert hits == {0, 1}


def test_normalize_tags_repairs_namespace():
    from rulesmith.author import normalize_tags

    assert normalize_tags(["T1059.001", "Execution", "defense_evasion", "attack.T1003", "nonsense", "cve.2024-1234"]) == [
        "attack.t1059.001",
        "attack.execution",
        "attack.defense-evasion",
        "attack.t1003",
        "cve.2024-1234",
    ]


def test_decode_double_escaped_only_touches_double_encoded_strings():
    from rulesmith.author import clean_event, decode_double_escaped

    # Model wrote two backslashes per separator and escaped quotes: undo one level.
    assert decode_double_escaped("C:\\\\Windows\\\\System32\\\\cmd.exe") == "C:\\Windows\\System32\\cmd.exe"
    assert decode_double_escaped('rundll32.exe \\"C:\\\\Users\\\\j\\\\x.dll\\",StartW') == 'rundll32.exe "C:\\Users\\j\\x.dll",StartW'
    assert decode_double_escaped("\\\\\\\\server\\\\share") == "\\\\server\\share"
    # Correct strings are untouched, including UNC paths and plain text.
    assert decode_double_escaped("C:\\Windows\\cmd.exe") == "C:\\Windows\\cmd.exe"
    assert decode_double_escaped("\\\\server\\share\\x.dll") == "\\\\server\\share\\x.dll"
    assert decode_double_escaped("whoami /all") == "whoami /all"
    ev = clean_event({"Image": "C:\\\\x\\\\a.exe", "ProcessId": 4, "Tags": ["C:\\\\y"]})
    assert ev == {"Image": "C:\\x\\a.exe", "ProcessId": 4, "Tags": ["C:\\y"]}


def test_normalize_tags_strips_leaked_punctuation():
    from rulesmith.author import normalize_tags

    assert normalize_tags(["attack.t1547.001],", "attack.persistence\""]) == ["attack.t1547.001", "attack.persistence"]


def test_explain_selections_names_the_failing_selection():
    import yaml

    from rulesmith.validate import explain_selections

    raw = yaml.safe_load(GOOD_RULE)
    # The event matches the child selection but has no Office parent and no ParentImage at all.
    event = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell -enc AAA"}
    why = explain_selections(raw, event)
    assert "selection_child=match" in why
    assert "selection_parent=NO MATCH (event lacks ParentImage)" in why


def test_validate_reports_per_selection_reason_for_missed_positive():
    draft = RuleDraft(candidate_id="D1", sigma_yaml=GOOD_RULE, tests=[TestEvent(id="P1", label="positive", description="no parent", event={"Image": "C:\\x\\powershell.exe", "CommandLine": "powershell -enc AAA"})])
    report = validate_rule(draft, corpus=None)
    msg = next(i.message for i in report.issues if i.code == "positive_missed")
    assert "selection_parent=NO MATCH" in msg


def test_refang_and_clean_detection():
    from rulesmith.author import clean_detection, refang

    assert refang("cdn.quietledger[.]net") == "cdn.quietledger.net"
    assert refang("hxxps://evil(.)com/a") == "https://evil.com/a"
    assert refang("C:\\Windows\\cmd.exe") == "C:\\Windows\\cmd.exe"
    det = {"selection": {"DestinationHostname|endswith": [".evil[.]com"], "ConditionList": []}, "condition": "selection"}
    assert clean_detection(det) == {"selection": {"DestinationHostname|endswith": [".evil.com"]}, "condition": "selection"}


def test_check_rule_flags_correlation_written_as_single_rule():
    from rulesmith.validate import check_rule

    seq = """
title: Backdoor user sequence
logsource: {product: aws, service: cloudtrail}
detection:
  selection_create_user: {eventName: CreateUser}
  selection_create_key: {eventName: CreateAccessKey}
  timeframe: {within: 600}
  condition: selection_create_user and selection_create_key and timeframe
"""
    rule, issues = check_rule(seq, corpus=None) if False else check_rule(seq)
    codes = {i.code for i in issues}
    assert rule is None
    assert "contradictory_selections" in codes and "correlation_not_supported" in codes
    assert any("ONE event" in i.message for i in issues)


def test_check_rule_flags_field_names_in_condition():
    from rulesmith.validate import check_rule

    bad = GOOD_RULE.replace("condition: selection_parent and selection_child", "condition: selection_parent and selection_child and CommandLine")
    rule, issues = check_rule(bad)
    assert rule is None
    assert any(i.code == "condition_unknown_name" and "CommandLine" in i.message for i in issues)
    # wildcard references to selections stay valid
    ok = GOOD_RULE.replace("condition: selection_parent and selection_child", "condition: all of selection_*")
    rule, issues = check_rule(ok)
    assert rule is not None and not any(i.code == "condition_unknown_name" for i in issues)


def test_explain_selections_names_failing_field_within_selection():
    import yaml

    from rulesmith.validate import explain_selections

    raw = yaml.safe_load(GOOD_RULE)
    # Office parent is right but the command line is not encoded: the child selection fails on CommandLine only.
    event = {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Office\\WINWORD.EXE", "CommandLine": "powershell -File ok.ps1"}
    why = explain_selections(raw, event)
    assert "selection_parent=match" in why
    assert "selection_child=NO MATCH (failing field tests: CommandLine|contains" in why


def test_check_rule_flags_anded_endswith_on_different_binaries():
    from rulesmith.validate import check_rule

    multi = """
title: Three LOLBins at once
logsource: {category: process_creation, product: windows}
detection:
  selection_vss: {'Image|endswith': '\\vssadmin.exe', 'CommandLine|contains': 'delete shadows'}
  selection_bcd: {'Image|endswith': '\\bcdedit.exe', 'CommandLine|contains': 'bootstatuspolicy'}
  condition: selection_vss and selection_bcd
"""
    rule, issues = check_rule(multi)
    assert rule is None and any(i.code == "contradictory_selections" and "Image|endswith" in i.message for i in issues)
    # Compatible suffixes (one is a suffix of the other) are allowed.
    ok = multi.replace("'\\bcdedit.exe'", "'\\system32\\vssadmin.exe'")
    rule, issues = check_rule(ok)
    assert not any(i.code == "contradictory_selections" for i in issues)


def test_check_rule_flags_aggregation_block():
    from rulesmith.validate import check_rule

    agg = """
title: RDP burst
logsource: {product: windows, service: security}
detection:
  failed: {EventID: 4625, LogonType: 10}
  time_window: {Selection: failed, Condition: 'count(failed) > 100'}
  condition: time_window
"""
    rule, issues = check_rule(agg)
    assert rule is None and any(i.code == "correlation_not_supported" for i in issues)
