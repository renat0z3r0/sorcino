from __future__ import annotations

from typing import TYPE_CHECKING

import aiohttp

from checks.models import Severity, VulnFinding
from checks.openclaw_profile import OpenClawProfile, load_profile
from utils.http import read_capped

if TYPE_CHECKING:
    from checks.evidence import EvidenceCollector


async def check_auth_bypass(
    base_url: str,
    session: aiohttp.ClientSession,
    evidence: EvidenceCollector | None = None,
    profile: OpenClawProfile | None = None,
) -> list[VulnFinding]:
    profile = profile or load_profile()
    findings: list[VulnFinding] = []

    # WebSocket auth is owned solely by check_websocket_auth (single owner, no
    # duplicate probe). This check covers HTTP endpoints + trusted-proxy only.

    # HTTP endpoints from the profile.
    for ep in profile.http_endpoints:
        if ep.method != "GET":
            continue
        try:
            findings.extend(await _check_http(f"{base_url}{ep.path}", ep, profile, session))
        except Exception:
            continue

    # Trusted-proxy header spoofing (data-driven; no-op unless headers configured).
    try:
        findings.extend(await _check_trusted_proxy(base_url, profile, session))
    except Exception:
        pass

    return findings


def _is_html_response(content_type: str, body: str) -> bool:
    """Detect HTML responses (SPA catch-all, error pages, etc.)."""
    ct = content_type.lower()
    if "text/html" in ct:
        return True
    stripped = body.strip().lower()
    return stripped.startswith("<!doctype") or stripped.startswith("<html")


async def _check_http(
    url: str,
    endpoint,
    profile: OpenClawProfile,
    session: aiohttp.ClientSession,
) -> list[VulnFinding]:
    findings: list[VulnFinding] = []

    try:
        async with session.get(url) as resp:
            if resp.status != 200:
                return findings

            content_type = resp.headers.get("Content-Type", "")
            body = await read_capped(resp)

            if _is_html_response(content_type, body):
                return findings

            has_scope = profile.has_operator_scope(body)
            has_sensitive = has_scope or any(ind in body for ind in profile.sensitive_indicators)

            # Privileged operator scopes without auth is the strongest signal.
            if has_scope:
                severity = Severity.CRITICAL
            elif has_sensitive:
                severity = endpoint.severity
            else:
                severity = Severity.MEDIUM

            findings.append(VulnFinding(
                check_name="auth_bypass",
                severity=severity,
                title=f"Unauthenticated access to {endpoint.name}",
                description=f"The endpoint {url} is accessible without authentication.",
                evidence=(
                    f"HTTP {resp.status}, Content-Type: {content_type}, "
                    f"operator_scope={has_scope}, sensitive={has_sensitive}, preview: {body[:150]}"
                ),
                remediation="Configure gateway authentication and restrict endpoint access.",
                cvss_estimate=9.1 if severity == Severity.CRITICAL else 7.5,
            ))
    except aiohttp.ClientError:
        pass

    return findings


async def _check_trusted_proxy(
    base_url: str,
    profile: OpenClawProfile,
    session: aiohttp.ClientSession,
) -> list[VulnFinding]:
    """Probe for trusted-proxy identity-header spoofing.

    Only runs when identity header names are configured in the profile — the
    real header name is not publicly documented, so by default this is a no-op
    rather than a speculative claim.
    """
    findings: list[VulnFinding] = []
    if not profile.trusted_proxy_headers:
        return findings

    target = next((e for e in profile.http_endpoints if e.requires_auth and e.method == "GET"), None)
    if target is None:
        return findings

    spoof_headers = {h: "admin" for h in profile.trusted_proxy_headers}
    url = f"{base_url}{target.path}"
    try:
        async with session.get(url, headers=spoof_headers) as resp:
            if resp.status == 200:
                body = await read_capped(resp)
                if not _is_html_response(resp.headers.get("Content-Type", ""), body):
                    findings.append(VulnFinding(
                        check_name="auth_bypass",
                        severity=Severity.MEDIUM,
                        title="Possible trusted-proxy identity header spoofing",
                        description=(
                            f"Authenticated endpoint {target.path} returned 200 when supplied "
                            f"forged identity headers ({', '.join(profile.trusted_proxy_headers)}). "
                            "If the gateway runs in trusted-proxy mode without a real proxy in "
                            "front, identity can be spoofed."
                        ),
                        evidence=f"HTTP 200 with spoofed headers, preview: {body[:120]}",
                        remediation=(
                            "Ensure trusted-proxy mode is only used behind an identity-aware "
                            "reverse proxy that strips client-supplied identity headers."
                        ),
                        cvss_estimate=6.5,
                    ))
    except aiohttp.ClientError:
        pass

    return findings
