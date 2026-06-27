from fingerprint.matcher import SignatureMatcher

M = SignatureMatcher()


def _names(matches):
    return {m.service_name for m in matches}


def test_extra_paths_are_gated_by_port():
    # Ollama's /api/tags is probed on 11434, not on an unrelated port.
    assert "/api/tags" in M.extra_paths_for_port(11434)
    assert "/api/tags" not in M.extra_paths_for_port(443)
    # LiteLLM on 4000; MCP has no ports -> probed on every port.
    assert "/model/info" in M.extra_paths_for_port(4000)
    assert "/mcp" in M.extra_paths_for_port(11434)
    assert "/mcp" in M.extra_paths_for_port(443)
    # POST-only endpoints (e.g. ollama /api/generate) are never probed.
    assert "/api/generate" not in M.extra_paths_for_port(11434)


def test_new_llm_signatures_match():
    cases = [
        (3000, '{"router":"text-generation-router"}', "/info", "Text Generation Inference"),
        (8080, '{"default_generation_settings":{},"chat_template_caps":{}}', "/props", "llama.cpp server"),
        (1234, '[{"compatibility_type":"gguf"}]', "/api/v0/models", "LM Studio"),
        (1337, '{"info":{"title":"Jan API Server Endpoints"}}', "/openapi.json", "Jan"),
        (3000, "<title>Flowise - Build AI Agents, Visually</title>", "/", "Flowise"),
        (4891, '{"data":[{"owned_by":"humanity"}]}', "/v1/models", "GPT4All"),
        (9997, '{"auth": true}', "/v1/cluster/auth", "Xinference"),
    ]
    for port, body, path, name in cases:
        assert name in _names(M.match(port=port, headers={}, body=body, url_path=path)), name


def test_ollama_endpoint_weight_now_fires():
    # /api/tags is a GET endpoint that was previously never probed.
    matches = M.match(port=11434, headers={}, body='{"models": [{"name":"llama3"}]}', url_path="/api/tags")
    assert "Ollama" in _names(matches)


def test_vllm_detected_via_metrics():
    body = "vllm:num_requests_running 3.0\nvllm:gpu_cache_usage_perc 0.42\n"
    matches = M.match(port=8000, headers={}, body=body, url_path="/metrics")
    assert "vLLM" in _names(matches)


def test_vllm_not_misfired_by_generic_models_list():
    # /v1/models alone (shared by all OpenAI servers) must not be enough.
    matches = M.match(port=8000, headers={}, body='{"object":"list","data":[]}', url_path="/v1/models")
    assert "vLLM" not in _names(matches)


def test_openwebui_detected_via_api_config():
    body = '{"status":true,"name":"Open WebUI","version":"0.5.0"}'
    matches = M.match(port=8080, headers={}, body=body, url_path="/api/config")
    assert "Open WebUI" in _names(matches)


def test_hermes_detected_via_capabilities():
    body = '{"object":"hermes.api_server.capabilities","features":{}}'
    matches = M.match(port=8642, headers={}, body=body, url_path="/v1/capabilities")
    assert "Hermes Agent" in _names(matches)


def test_hermes_detected_via_session_header():
    matches = M.match(port=8642, headers={"X-Hermes-Session-Key": "abc"}, body="", url_path="/")
    assert "Hermes Agent" in _names(matches)


def test_hermes_capabilities_path_is_probed():
    assert "/v1/capabilities" in M.extra_paths_for_port(8642)

