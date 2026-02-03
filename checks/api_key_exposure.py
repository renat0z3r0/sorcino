from __future__ import annotations
import asyncio
import re

import aiohttp

from checks.models import Severity, VulnFinding


API_KEY_PATTERNS = {
    "anthropic": r"sk-ant-[a-zA-Z0-9-]{80,}",
    "openai": r"sk-[a-zA-Z0-9]{48}",
    "openai_project": r"sk-proj-[a-zA-Z0-9]{48}",
    "google": r"AIza[a-zA-Z0-9_-]{35}",
    "huggingface": r"hf_[a-zA-Z0-9]{34}",
}

ENDPOINTS_TO_CHECK = [
    "/", "/health", "/status", "/api/config", "/config",
    "/debug", "/api/keys", "/v1/models", "/.env", "/env",
]


async def check_api_key_exposure(
    base_url: str,
    session: aiohttp.ClientSession,
) -> list[VulnFinding]:
    findings: list[VulnFinding] = []

    for path in ENDPOINTS_TO_CHECK:
        url = f"{base_url}{path}"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    continue

                body = await resp.text()
                headers = dict(resp.headers)

                for provider, pattern in API_KEY_PATTERNS.items():
                    for match in re.findall(pattern, body):
                        context_patterns = [
                            r'["\']?' + re.escape(match) + r'["\']?',
                            r'(key|token|api|secret).*' + re.escape(match[:10]),
                        ]
                        if any(re.search(cp, body, re.IGNORECASE) for cp in context_patterns):
                            findings.append(VulnFinding(
                                check_name="api_key_exposure",
                                severity=Severity.CRITICAL,
                                title=f"{provider.title()} API key exposed",
                                description=f"Found {provider} API key at {path}",
                                evidence=f"Key: {match[:8]}...{match[-4:]}",
                                remediation="Immediately rotate this API key and remove from public endpoints.",
                                cvss_estimate=9.8,
                            ))

                for header_name, header_value in headers.items():
                    for provider, pattern in API_KEY_PATTERNS.items():
                        if re.search(pattern, header_value):
                            findings.append(VulnFinding(
                                check_name="api_key_exposure",
                                severity=Severity.CRITICAL,
                                title=f"{provider.title()} API key in HTTP header",
                                description=f"Found {provider} API key in {header_name} header",
                                evidence=f"Header: {header_name}: {header_value[:15]}...",
                                remediation="Remove API keys from response headers.",
                                cvss_estimate=9.8,
                            ))

        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue

    return findings
