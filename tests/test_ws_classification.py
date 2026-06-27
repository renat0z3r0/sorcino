from checks.ws_probe import classify, WSObservation, WSResult
from checks.openclaw_profile import load_profile

P = load_profile()


def test_fail_closed_on_1008():
    obs = WSObservation(connected=True, close_code=1008, close_reason="bye")
    assert classify(obs, P) is WSResult.FAIL_CLOSED


def test_fail_closed_on_reason_in_close():
    obs = WSObservation(connected=True, close_reason="gateway token missing")
    assert classify(obs, P) is WSResult.FAIL_CLOSED


def test_fail_closed_when_response_is_auth_error():
    obs = WSObservation(connected=True, response="unauthorized")
    assert classify(obs, P) is WSResult.FAIL_CLOSED


def test_unauth_rpc_on_real_response():
    obs = WSObservation(connected=True, response='{"jsonrpc":"2.0","result":{"status":"ok"}}')
    assert classify(obs, P) is WSResult.UNAUTH_RPC


def test_non_jsonrpc_frame_is_not_critical():
    # A greeting / echo WebSocket must NOT be flagged as unauthenticated RPC.
    for greeting in ('{"type":"welcome"}', "hello", '{"msg":"echo: hi"}', "[1,2,3]"):
        assert classify(WSObservation(connected=True, response=greeting), P) is WSResult.ACCEPTED_NO_RESPONSE


def test_accepted_no_response():
    assert classify(WSObservation(connected=True), P) is WSResult.ACCEPTED_NO_RESPONSE


def test_unreachable():
    assert classify(WSObservation(connected=False), P) is WSResult.UNREACHABLE
