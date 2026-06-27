from dataclasses import dataclass

from checks.hermes import check_hermes
from checks.models import Severity


@dataclass
class FakeProbe:
    url: str
    status_code: int
    body_preview: str


def _by_check(findings, name):
    return [f for f in findings if f.check_name == name]


def test_unauth_api_capabilities_is_critical():
    probes = [FakeProbe("http://1.2.3.4:8642/v1/capabilities", 200,
                        '{"object":"hermes.api_server.capabilities"}')]
    f = _by_check(check_hermes(probes), "hermes_auth")
    assert f and f[0].severity is Severity.CRITICAL


def test_gated_api_not_flagged():
    # 401 (auth enforced) must NOT be flagged.
    probes = [FakeProbe("http://1.2.3.4:8642/v1/capabilities", 401, '{"detail":"unauthorized"}')]
    assert _by_check(check_hermes(probes), "hermes_auth") == []


def test_exposed_dashboard_is_high():
    probes = [FakeProbe("http://1.2.3.4:9119/", 200, "<title>Web Dashboard | Hermes Agent</title>")]
    f = _by_check(check_hermes(probes), "hermes_dashboard")
    assert f and f[0].severity is Severity.HIGH


def test_unrelated_page_not_flagged():
    probes = [FakeProbe("http://1.2.3.4:8000/", 200, "<html>some other app</html>")]
    assert check_hermes(probes) == []
