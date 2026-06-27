from cli import _filter_findings
from checks.models import Severity, VulnFinding, SEVERITY_ORDER
from checks.mdns_discovery import findings_from_records
from checks.openclaw_profile import load_profile

P = load_profile()


def _finding(sev: Severity) -> VulnFinding:
    return VulnFinding(
        check_name="t", severity=sev, title="t", description="d",
        evidence="e", remediation="r",
    )


def test_severity_order_monotonic():
    vals = [SEVERITY_ORDER[s] for s in
            (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert vals == sorted(vals) and len(set(vals)) == 5


def test_filter_findings_threshold():
    findings = [_finding(s) for s in Severity]
    high_plus = _filter_findings(findings, Severity.HIGH)
    assert {f.severity for f in high_plus} == {Severity.HIGH, Severity.CRITICAL}


# --- mDNS findings ---

def test_clipath_leak_uses_correct_remediation_key():
    fs = findings_from_records(
        [{"name": "gw", "host": "10.0.0.1", "port": 18789, "txt": {"cliPath": "/Users/alice/openclaw"}}],
        P,
    )
    leak = next(f for f in fs if "cliPath" in f.title)
    assert leak.severity is Severity.MEDIUM
    assert "discovery.mdns.mode" in leak.remediation
    assert "gateway.discovery.mode" not in leak.remediation


def test_tls_advertisement_emitted():
    fs = findings_from_records(
        [{"name": "gw", "host": "10.0.0.1", "port": 18789, "txt": {"gatewayTls": "1"}}],
        P,
    )
    assert any("TLS gateway" in f.title for f in fs)


def test_clean_minimal_record_only_discovery_info():
    fs = findings_from_records(
        [{"name": "gw", "host": "10.0.0.1", "port": 18789, "txt": {"role": "gateway"}}],
        P,
    )
    # No sensitive-leak findings, just the discovery INFO record.
    assert all(f.severity is Severity.INFO for f in fs)
    assert any(f.title.startswith("OpenClaw Gateway discovered") for f in fs)
