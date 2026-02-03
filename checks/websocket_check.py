from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import websockets

from checks.models import Severity, VulnFinding

if TYPE_CHECKING:
    from checks.evidence import EvidenceCollector


TEST_MESSAGES = [
    '{"jsonrpc":"2.0","method":"ping","id":1}',
    '{"type":"ping"}',
    '{"action":"list_methods"}',
]


async def check_websocket_auth(
    base_url: str,
    ports: list[int] | None = None,
    evidence: EvidenceCollector | None = None,
) -> list[VulnFinding]:
    findings: list[VulnFinding] = []

    if ports is None:
        ports = [18789, 8080, 3000, 8000]

    host = base_url.replace("http://", "").replace("https://", "").split(":")[0]
    seen: set[str] = set()

    for port in ports:
        key = f"{host}:{port}"
        if key in seen:
            continue

        ws_url = f"ws://{host}:{port}/"

        try:
            async with websockets.connect(
                ws_url, close_timeout=5, open_timeout=5
            ) as ws:
                got_response = False
                for msg in TEST_MESSAGES:
                    try:
                        await ws.send(msg)
                        response = await asyncio.wait_for(ws.recv(), timeout=3)

                        if evidence is not None:
                            evidence.save_ws_response(ws_url, msg, response)

                        findings.append(VulnFinding(
                            check_name="websocket_auth",
                            severity=Severity.HIGH,
                            title="WebSocket accepts unauthenticated connections",
                            description=f"WebSocket at {ws_url} accepts connections without authentication and responds to messages.",
                            evidence=f"Sent: {msg[:50]}, Received: {response[:100]}",
                            remediation="Implement WebSocket authentication (token in handshake, first message auth).",
                        ))
                        got_response = True
                        break
                    except asyncio.TimeoutError:
                        continue

                if not got_response:
                    findings.append(VulnFinding(
                        check_name="websocket_auth",
                        severity=Severity.MEDIUM,
                        title="WebSocket accepts unauthenticated connections",
                        description=f"WebSocket at {ws_url} accepts connections without authentication.",
                        evidence="Connection established without credentials",
                        remediation="Implement WebSocket authentication.",
                    ))

                seen.add(key)

        except websockets.exceptions.InvalidStatusCode:
            pass
        except Exception:
            continue

    return findings
