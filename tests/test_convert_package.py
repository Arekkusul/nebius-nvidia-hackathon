"""Tests for SIEM conversion and packaging."""

from __future__ import annotations

import io
import json
import zipfile

from rulesmith.config import Settings
from rulesmith.convert import convert_rule_all
from rulesmith.llm import FakeLLM
from rulesmith.package import build_zip, markdown_report, navigator_layer, slugify
from rulesmith.pipeline import Pipeline, RunInput
from tests.fixtures import GOOD_YAML, REPORT_TEXT, responses_all_good


def test_convert_rule_all_targets_and_isolated_errors():
    queries, errors = convert_rule_all(GOOD_YAML)
    assert set(queries) == {"splunk", "elasticsearch", "kusto", "sqlite"}
    assert errors == {}
    assert 'ParentImage IN (' in queries["splunk"]
    assert "InitiatingProcessFolderPath" in queries["kusto"]
    # unsupported logsource for the XDR pipeline fails only that target
    q2, e2 = convert_rule_all(GOOD_YAML.replace("category: process_creation", "category: wmi_event"))
    assert "splunk" in q2 and "sqlite" in q2
    assert "kusto" in e2 and "kusto" not in q2
    q3, e3 = convert_rule_all("title: [bad")
    assert q3 == {} and len(e3) == 4


def test_package_outputs(tmp_path):
    result = Pipeline(Settings(runs_dir=tmp_path), FakeLLM(responses_all_good())).run(RunInput(mode="text", value=REPORT_TEXT))
    layer = navigator_layer(result)
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"][0]["techniqueID"] == "T1059.001"
    assert layer["techniques"][0]["color"] == "#2e8b57"
    md = markdown_report(result)
    assert "# RuleSmith detection pack" in md and "```yaml" in md and "Red-team analysis" in md
    blob = build_zip(result)
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        names = zf.namelist()
        slug = slugify(result.rules[0].title)
        assert f"rules/{slug}.yml" in names and f"queries/{slug}.kql" in names and f"tests/{slug}.jsonl" in names
        assert "navigator_layer.json" in names and "report.md" in names and "run.json" in names
        tests = [json.loads(line) for line in zf.read(f"tests/{slug}.jsonl").decode().splitlines() if line]
        assert len(tests) == 8 and tests[0]["label"] == "positive"
        assert json.loads(zf.read("run.json"))["run_id"] == result.run_id
    assert slugify("Rundll32 Execution Of DLL From Temp!") == "rundll32_execution_of_dll_from_temp"
