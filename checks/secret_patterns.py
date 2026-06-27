"""Provider API-key patterns, shared by the secret-detection checks.

Kept deliberately specific (provider prefix + a minimum length) rather than the
old broad ``sk-[a-zA-Z0-9]{20,}``, which flooded results with false positives.
Negative lookaheads stop the generic OpenAI pattern from swallowing Anthropic /
project / service keys, so a single key is reported under one provider only.
"""
from __future__ import annotations

API_KEY_PATTERNS: dict[str, str] = {
    # Anthropic: sk-ant-api03-<base64url> — includes '-' and '_'.
    "anthropic": r"sk-ant-[A-Za-z0-9_-]{20,}",
    # OpenAI project / service-account keys carry their own infixes.
    "openai_project": r"sk-proj-[A-Za-z0-9_-]{20,}",
    "openai_service": r"sk-svcacct-[A-Za-z0-9_-]{20,}",
    # Generic OpenAI key, excluding the more specific prefixes above.
    "openai": r"sk-(?!ant-|proj-|svcacct-)[A-Za-z0-9]{20,}",
    "google": r"AIza[0-9A-Za-z_-]{35}",
    "huggingface": r"hf_[A-Za-z0-9]{30,}",
}
