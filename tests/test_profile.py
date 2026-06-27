from checks.models import Severity
from checks.openclaw_profile import load_profile, OpenClawProfile


def test_profile_loads_real_yaml():
    p = load_profile()
    assert "trusted-proxy" in p.auth_modes
    assert p.ws_close_codes.get(1008) == "fail_closed"
    assert "operator.admin" in p.operator_scopes
    assert p.verified_ports == (18789,)
    assert p.mdns.remediation_key == "discovery.mdns.mode"
    assert p.mdns.service_type.startswith("_openclaw-gw")


def test_endpoints_have_expected_paths():
    paths = {e.path for e in load_profile().http_endpoints}
    assert {"/tools/invoke", "/api/v1/admin/rpc", "/v1/models"} <= paths


def test_txt_key_severity():
    tk = load_profile().mdns.txt_key("cliPath")
    assert tk is not None and tk.severity is Severity.MEDIUM


def test_is_fail_closed_reason_case_insensitive():
    p = load_profile()
    assert p.is_fail_closed_reason("Gateway Token Missing")
    assert not p.is_fail_closed_reason("welcome")


def test_has_operator_scope():
    p = load_profile()
    assert p.has_operator_scope('{"scopes":["operator.write"]}')
    assert not p.has_operator_scope("nothing privileged here")


def test_missing_file_falls_back_safely():
    p = load_profile("/nonexistent/openclaw_surface.yaml")
    assert isinstance(p, OpenClawProfile)
    # Fallback still provides safe mDNS defaults.
    assert p.mdns.service_type == "_openclaw-gw._tcp.local."
    assert p.ws_rpc_probe  # non-empty
    # ...and still recognises fail-closed WS, so a 1008 close isn't a false positive.
    assert p.ws_close_codes.get(1008) == "fail_closed"
    assert p.is_fail_closed_reason("gateway token missing")
