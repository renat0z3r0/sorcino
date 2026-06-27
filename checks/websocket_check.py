from __future__ import annotations

from typing import TYPE_CHECKING

from checks.models import Severity, VulnFinding
from checks.openclaw_profile import OpenClawProfile, load_profile
from checks.ws_probe import WSResult, probe_ws

if TYPE_CHECKING:
    from checks.evidence import EvidenceCollector


async def check_websocket_auth(
    base_url: str,
    ports: list[int] | None = None,
    evidence: EvidenceCollector | None = None,
    profile: OpenClawProfile | None = None,
) -> list[VulnFinding]:
    """Probe candidate ports for unauthenticated WebSocket gateways.

    Shares the close-code classification with ``auth_bypass`` via ``probe_ws``
    so a fail-closed (1008) gateway is no longer mistaken for a bypass.
    """
    profile = profile or load_profile()
    findings: list[VulnFinding] = []

    if ports is None:
        ports = list(profile.verified_ports) or [18789]

    host = base_url.replace("http://", "").replace("https://", "").split(":")[0]
    seen: set[int] = set()

    for port in ports:
        if port in seen:
            continue
        seen.add(port)

        result, obs = await probe_ws(host, port, "/", profile=profile, evidence=evidence)

        if result is WSResult.UNAUTH_RPC:
            findings.append(VulnFinding(
                check_name="websocket_auth",
                severity=Severity.CRITICAL,
                title="WebSocket accepts unauthenticated control",
                description=(
                    f"WebSocket at {obs.scheme}://{host}:{port}/ answered an RPC request "
                    "without authentication."
                ),
                evidence=f"Received: {(obs.response or '')[:120]}",
                remediation="Implement WebSocket authentication (token in handshake / first message).",
                cvss_estimate=9.6,
            ))
        elif result is WSResult.ACCEPTED_NO_RESPONSE:
            findings.append(VulnFinding(
                check_name="websocket_auth",
                severity=Severity.MEDIUM,
                title="WebSocket connection accepted, auth state unclear",
                description=(
                    f"WebSocket at {obs.scheme}://{host}:{port}/ accepted the connection "
                    "but did not respond. Auth enforcement could not be confirmed."
                ),
                evidence="Connection established without credentials",
                remediation="Implement WebSocket authentication and verify it is enforced.",
                cvss_estimate=5.3,
            ))
        elif result is WSResult.FAIL_CLOSED:
            # Auth is being enforced (good); only notable because the gateway is
            # reachable over the network at all (default bind is loopback).
            findings.append(VulnFinding(
                check_name="websocket_auth",
                severity=Severity.LOW,
                title="WebSocket exposed to network (authentication enforced)",
                description=(
                    f"WebSocket at {obs.scheme}://{host}:{port}/ is reachable but rejects "
                    "unauthenticated connections (fail-closed)."
                ),
                evidence=f"close_code={obs.close_code} reason={obs.close_reason!r}",
                remediation="Bind to loopback / front remote access with a tunnel if exposure is unintended.",
                cvss_estimate=3.1,
            ))
        # UNREACHABLE => no finding.

    return findings
