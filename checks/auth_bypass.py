from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import aiohttp
import websockets

from checks.models import Severity, VulnFinding

if TYPE_CHECKING:
    from checks.evidence import EvidenceCollector


OPENCLAW_ENDPOINTS = [
    ("/", "WS", "Gateway WebSocket", Severity.CRITICAL),
    ("/webchat", "GET", "WebChat UI", Severity.HIGH),
    ("/dashboard", "GET", "Control Dashboard", Severity.HIGH),
    ("/api/config", "GET", "Gateway Configuration", Severity.CRITICAL),
    ("/api/sessions", "GET", "Sessions listing", Severity.HIGH),
    ("/health", "GET", "Health endpoint", Severity.LOW),
    ("/credentials", "GET", "Credentials directory", Severity.CRITICAL),
    ("/debug", "GET", "Debug Endpoint", Severity.MEDIUM),
    ("/metrics", "GET", "Prometheus Metrics", Severity.MEDIUM),
]

SENSITIVE_INDICATORS = (
    '"channels"', '"whatsapp"', '"telegram"',
    '"token"', '"apiKey"', "ANTHROPIC_API_KEY",
    '"sessions"', '"credentials"',
)


async def check_auth_bypass(
    base_url: str,
    session: aiohttp.ClientSession,
    evidence: EvidenceCollector | None = None,
) -> list[VulnFinding]:
    findings: list[VulnFinding] = []

    for path, method, name, severity in OPENCLAW_ENDPOINTS:
        url = f"{base_url}{path}"

        try:
            if method == "WS":
                findings.extend(await _check_ws(url, evidence))
            elif method == "GET":
                findings.extend(await _check_http(url, name, severity, session))
        except Exception:
            continue

    return findings


async def _check_ws(
    url: str,
    evidence: EvidenceCollector | None = None,
) -> list[VulnFinding]:
    findings: list[VulnFinding] = []
    ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
    rpc_msg = '{"jsonrpc":"2.0","method":"status","id":1}'

    try:
        async with websockets.connect(ws_url, close_timeout=5, open_timeout=5) as ws:
            await ws.send(rpc_msg)
            try:
                response = await asyncio.wait_for(ws.recv(), timeout=3)

                if evidence is not None:
                    evidence.save_ws_response(ws_url, rpc_msg, response)

                findings.append(VulnFinding(
                    check_name="auth_bypass",
                    severity=Severity.CRITICAL,
                    title="OpenClaw Gateway WebSocket accessible without authentication",
                    description="The Gateway WebSocket accepts connections without a token. This allows full control of the assistant.",
                    evidence=f"WS connected, RPC response: {response[:200]}",
                    remediation="Set gateway.auth.mode to 'token' or 'password' in openclaw.json",
                    cvss_estimate=9.8,
                ))
            except asyncio.TimeoutError:
                findings.append(VulnFinding(
                    check_name="auth_bypass",
                    severity=Severity.HIGH,
                    title="OpenClaw Gateway WebSocket accepts unauthenticated connections",
                    description="The Gateway WebSocket accepts connections without a token.",
                    evidence="WS connection established without authentication",
                    remediation="Set gateway.auth.mode to 'token' or 'password' in openclaw.json",
                    cvss_estimate=8.5,
                ))
    except websockets.exceptions.InvalidStatusCode:
        pass
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
    name: str,
    severity: Severity,
    session: aiohttp.ClientSession,
) -> list[VulnFinding]:
    findings: list[VulnFinding] = []

    try:
        async with session.get(url) as resp:
            if resp.status == 200:
                content_type = resp.headers.get("Content-Type", "")
                body = await resp.text()

                if _is_html_response(content_type, body):
                    return findings

                has_sensitive = any(ind in body for ind in SENSITIVE_INDICATORS)

                findings.append(VulnFinding(
                    check_name="auth_bypass",
                    severity=severity if has_sensitive else Severity.MEDIUM,
                    title=f"Unauthenticated access to {name}",
                    description=f"The endpoint {url} is accessible without authentication.",
                    evidence=f"HTTP {resp.status}, Content-Type: {content_type}, sensitive_data={has_sensitive}, preview: {body[:150]}",
                    remediation="Configure gateway authentication and restrict endpoint access.",
                    cvss_estimate=9.1 if severity == Severity.CRITICAL else 7.5,
                ))
    except aiohttp.ClientError:
        pass

    return findings
