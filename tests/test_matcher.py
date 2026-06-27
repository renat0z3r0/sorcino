from fingerprint.matcher import SignatureMatcher

M = SignatureMatcher()


def _names(matches):
    return {m.service_name for m in matches}


def test_openclaw_identified_by_body_and_port():
    matches = M.match(port=18789, headers={}, body="OpenClaw gateway", url_path="/")
    assert "OpenClaw" in _names(matches)


def test_headers_check_is_honored():
    # The "/" endpoint declares a headers_check for Upgrade: websocket that the
    # matcher previously ignored.
    with_hdr = M.match(port=18789, headers={"Upgrade": "websocket"}, body="openclaw", url_path="/")
    without = M.match(port=18789, headers={}, body="openclaw", url_path="/")
    oc_with = next(m for m in with_hdr if m.service_name == "OpenClaw")
    oc_without = next(m for m in without if m.service_name == "OpenClaw")
    assert oc_with.confidence >= oc_without.confidence
    assert any("header_check" in s for s in oc_with.matched_signals)


def test_ollama_signature():
    matches = M.match(
        port=11434, headers={}, body='{"models": []}', url_path="/api/tags"
    )
    assert "Ollama" in _names(matches)


def test_below_threshold_not_matched():
    matches = M.match(port=22, headers={}, body="ssh-2.0", url_path="/")
    assert _names(matches) == set()


def test_confidence_capped_at_100():
    matches = M.match(
        port=18789,
        headers={"x-openclaw-version": "1", "Upgrade": "websocket"},
        body="OpenClaw Moltbot Clawdbot OPENCLAW_GATEWAY ws://127.0.0.1:18789",
        url_path="/",
    )
    assert all(m.confidence <= 100 for m in matches)
