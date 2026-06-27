import re

from checks.secret_patterns import API_KEY_PATTERNS


def _match(name: str, text: str):
    return re.search(API_KEY_PATTERNS[name], text)


def test_anthropic_key_matches_anthropic_only():
    key = "sk-ant-api03-" + "A1b2C3d4_-" * 5
    assert _match("anthropic", key)
    # The generic openai pattern must NOT swallow an anthropic key.
    assert not _match("openai", key)


def test_project_key_not_matched_by_generic_openai():
    key = "sk-proj-" + "abcDEF012345" * 3
    assert _match("openai_project", key)
    assert not _match("openai", key)


def test_service_account_key():
    key = "sk-svcacct-" + "abcDEF012345" * 3
    assert _match("openai_service", key)
    assert not _match("openai", key)


def test_generic_openai_key():
    key = "sk-" + "A" * 48
    assert _match("openai", key)


def test_short_sk_token_is_not_flagged():
    # The old broad pattern flagged this; the new one requires >= 20 chars.
    assert not _match("openai", "sk-abc123")


def test_random_sk_word_not_matched():
    assert not _match("openai", "ask-me-anything please")


def test_google_and_hf():
    assert _match("google", "AIza" + "B" * 35)
    assert _match("huggingface", "hf_" + "c" * 34)
