from __future__ import annotations

import re
from typing import TYPE_CHECKING

import aiohttp

from checks.models import Severity, VulnFinding
from checks.secret_patterns import API_KEY_PATTERNS
from utils.http import read_capped

if TYPE_CHECKING:
    from checks.evidence import EvidenceCollector


DISCLOSURE_PATTERNS = [
    (r"DEBUG\s*[=:]\s*[Tt]rue", "Debug mode enabled", Severity.MEDIUM),
    (r"NODE_ENV\s*[=:]\s*development", "Development mode", Severity.MEDIUM),
    (r"stack.*at\s+\w+\s+\(", "Stack trace exposed", Severity.LOW),
    (r"ANTHROPIC_API_KEY", "Anthropic API key reference", Severity.HIGH),
    (r"OPENAI_API_KEY", "OpenAI API key reference", Severity.HIGH),
    # Reuse the shared, specific key patterns instead of the old broad
    # `sk-[a-zA-Z0-9]{20,}` that flagged any random sk-prefixed token.
    (API_KEY_PATTERNS["anthropic"], "Anthropic API key pattern", Severity.CRITICAL),
    (API_KEY_PATTERNS["openai"], "OpenAI API key pattern", Severity.CRITICAL),
    (r'"password"\s*:\s*"[^"]+"', "Password in response", Severity.CRITICAL),
    (r'"secret"\s*:\s*"[^"]+"', "Secret in response", Severity.HIGH),
    (r"version.*\d+\.\d+\.\d+", "Version disclosure", Severity.INFO),
    (r'"error".*"message".*exception', "Detailed error message", Severity.LOW),
]

SENSITIVE_FILES = [
    ("/.env", "Environment file"),
    ("/.git/config", "Git config"),
    ("/config.json", "Config file"),
    ("/config.yaml", "Config file"),
    ("/secrets.json", "Secrets file"),
    ("/.aws/credentials", "AWS credentials"),
    ("/docker-compose.yml", "Docker compose (may contain secrets)"),
]

_FILE_VALIDATORS = {
    "/.env": lambda b: bool(re.search(r"^[A-Z_]+=.+", b, re.MULTILINE)),
    "/.git/config": lambda b: "[core]" in b,
    "/config.json": lambda b: b.lstrip().startswith("{"),
    "/config.yaml": lambda b: bool(re.search(r"^\w+:", b, re.MULTILINE)),
    "/secrets.json": lambda b: b.lstrip().startswith("{"),
    "/.aws/credentials": lambda b: "[default]" in b or "aws_access_key_id" in b.lower(),
    "/docker-compose.yml": lambda b: "services:" in b or "version:" in b,
}


def _is_spa_catchall(content_type: str, body: str) -> bool:
    ct = content_type.lower() if content_type else ""
    if "text/html" in ct:
        return True
    body_start = body[:256].lstrip().lower()
    if body_start.startswith("<!doctype") or body_start.startswith("<html"):
        return True
    if "openclaw-app" in body:
        return True
    return False


async def check_info_disclosure(
    base_url: str,
    session: aiohttp.ClientSession,
    probe_results: list,
    evidence: EvidenceCollector | None = None,
) -> list[VulnFinding]:
    findings: list[VulnFinding] = []

    for probe in probe_results:
        body = probe.body_preview

        for pattern, title, severity in DISCLOSURE_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                sanitized = matches[0]
                if "sk-" in sanitized.lower():
                    sanitized = sanitized[:10] + "..." + sanitized[-4:]

                findings.append(VulnFinding(
                    check_name="info_disclosure",
                    severity=severity,
                    title=title,
                    description=f"Found sensitive information at {probe.url}",
                    evidence=f"Pattern match: {sanitized}",
                    remediation="Remove sensitive information from responses. Disable debug mode in production.",
                ))

    for path, name in SENSITIVE_FILES:
        url = f"{base_url}{path}"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    continue

                body = await read_capped(resp)
                ct = resp.headers.get("Content-Type", "")

                if len(body) <= 10 or "not found" in body.lower():
                    continue

                if _is_spa_catchall(ct, body):
                    continue

                validator = _FILE_VALIDATORS.get(path)
                if validator and not validator(body):
                    continue

                if evidence is not None:
                    evidence.save_file(path, body, url)

                findings.append(VulnFinding(
                    check_name="info_disclosure",
                    severity=Severity.HIGH,
                    title=f"{name} exposed",
                    description=f"Sensitive file accessible at {path}",
                    evidence=f"File content preview: {body[:100]}...",
                    remediation=f"Block access to {path} via web server configuration.",
                ))
        except Exception:
            continue

    return findings
