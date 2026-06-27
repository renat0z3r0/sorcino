"""Hermes Agent (NousResearch) auth checks.

Pure: scans the probe results already gathered, so it adds no extra requests.
Two documented misconfigurations:
  - API server (8642) must require API_SERVER_KEY on *every* deployment, so an
    unauthenticated 200 on /v1/capabilities is a real auth bypass.
  - Web dashboard (9119) reachable over the network leaks the .env (API keys)
    when bound non-loopback with --insecure.
"""
from __future__ import annotations

import urllib.parse

from checks.models import Severity, VulnFinding


def check_hermes(probe_results: list) -> list[VulnFinding]:
    findings: list[VulnFinding] = []

    for p in probe_results:
        path = urllib.parse.urlsplit(p.url).path
        body = p.body_preview or ""

        if path == "/v1/capabilities" and p.status_code == 200 and "hermes.api_server.capabilities" in body:
            findings.append(VulnFinding(
                check_name="hermes_auth",
                severity=Severity.CRITICAL,
                title="Hermes Agent API server accepts unauthenticated requests",
                description=(
                    "GET /v1/capabilities returned 200 without a bearer token. Hermes "
                    "requires API_SERVER_KEY for every deployment, so authentication is "
                    "disabled — the OpenAI-compatible API and agent control are exposed."
                ),
                evidence=f"HTTP 200 at {p.url}, capabilities object present",
                remediation="Set API_SERVER_KEY and require the Authorization bearer on the API server.",
                cvss_estimate=9.4,
            ))

        if path == "/" and p.status_code == 200 and "Web Dashboard | Hermes Agent" in body:
            findings.append(VulnFinding(
                check_name="hermes_dashboard",
                severity=Severity.HIGH,
                title="Hermes Agent web dashboard reachable over the network",
                description=(
                    "The Hermes dashboard served its UI to an unauthenticated network "
                    "request. Bound to a non-loopback address with --insecure it reads and "
                    "writes the .env (API keys and secrets)."
                ),
                evidence=f"HTTP 200 at {p.url}, dashboard title present",
                remediation=(
                    "Bind the dashboard to 127.0.0.1 (default) or behind its OAuth gate / a "
                    "VPN; never use --insecure on a public bind."
                ),
                cvss_estimate=7.5,
            ))

    return findings
