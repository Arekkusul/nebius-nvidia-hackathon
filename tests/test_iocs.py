"""IOC hygiene: the extraction model's indicator list is cleaned on construction."""

from __future__ import annotations

from rulesmith.models import IOC, ThreatReport, sanitize_iocs


def _report(iocs):
    return ThreatReport(title="t", summary="s", iocs=iocs)


def test_descriptions_placeholders_and_mistyped_values_are_dropped():
    cleaned = sanitize_iocs([
        IOC(type="ip", value="185.220.101.34"),
        IOC(type="ip", value="Tor exit node"),                     # a description, not an address
        IOC(type="ip", value="123456789012"),                      # an AWS account id labelled as an ip
        IOC(type="sha256", value="XMRig binary hash (not provided in report)"),
        IOC(type="url", value="https://github.com/..."),           # truncated placeholder on a benign host
        IOC(type="domain", value="CORP"),                          # single label: a NetBIOS name, not a domain
        IOC(type="domain", value="github.com"),                    # legitimate service
        IOC(type="domain", value="s3.amazonaws.com"),              # legitimate service, subdomain form
        IOC(type="domain", value="cdn-updates.quietledger[.]net"),  # defanged but valid
        IOC(type="domain", value="mega.co.nz"),
        IOC(type="domain", value="mega.co.nz"),                    # duplicate
        IOC(type="filename", value="/tmp/.x/kthreadd"),
        IOC(type="filename", value="the dropped binary was deleted after use."),
    ])
    assert [(i.type, i.value) for i in cleaned] == [
        ("ip", "185.220.101.34"),
        ("domain", "cdn-updates.quietledger[.]net"),
        ("domain", "mega.co.nz"),
        ("filename", "/tmp/.x/kthreadd"),
    ]


def test_hashes_must_be_hex_of_the_right_length():
    good = "5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
    cleaned = sanitize_iocs([IOC(type="sha256", value=good), IOC(type="sha256", value=good[:40]), IOC(type="md5", value="d41d8cd98f00b204e9800998ecf8427e")])
    assert [(i.type, i.value) for i in cleaned] == [("sha256", good), ("md5", "d41d8cd98f00b204e9800998ecf8427e")]


def test_threat_report_cleans_on_construction_and_on_json_load():
    r = _report([{"type": "ip", "value": "Tor exit node"}, {"type": "ip", "value": "10.10.14.7"}])
    assert [i.value for i in r.iocs] == ["10.10.14.7"]
    again = ThreatReport.model_validate_json(r.model_dump_json())
    assert [i.value for i in again.iocs] == ["10.10.14.7"]
