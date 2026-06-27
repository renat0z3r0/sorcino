"""Shared WebSocket probing + outcome classification for OpenClaw checks.

The gateway is fail-closed by default: it either refuses the handshake or
accepts the socket and immediately closes it with code 1008. Distinguishing
that healthy behaviour from a genuinely unauthenticated gateway is the whole
point of these checks, so the classification lives in one pure, testable place.
"""
from __future__ import annotations

import asyncio
import json
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

import websockets
import websockets.exceptions

from checks.models import Severity
from checks.openclaw_profile import OpenClawProfile, load_profile

if TYPE_CHECKING:
    from checks.evidence import EvidenceCollector

# websockets renamed the handshake-refused exception across versions. Prefer
# the modern name; only fall back to the deprecated one if it is unavailable
# (touching the deprecated alias would emit a DeprecationWarning).
def _refused_exceptions() -> tuple[type[Exception], ...]:
    modern = getattr(websockets.exceptions, "InvalidStatus", None)
    if modern is not None:
        return (modern,)
    legacy = getattr(websockets.exceptions, "InvalidStatusCode", None)
    return (legacy,) if legacy is not None else ()


_REFUSED_EXCEPTIONS: tuple[type[Exception], ...] = _refused_exceptions()


class WSResult(Enum):
    UNAUTH_RPC = "unauth_rpc"          # responded to RPC without a token -> real bug
    FAIL_CLOSED = "fail_closed"        # refused / closed 1008 -> auth enforced (OK)
    ACCEPTED_NO_RESPONSE = "accepted"  # socket open, no response -> auth state unclear
    UNREACHABLE = "unreachable"        # could not connect at all


@dataclass(frozen=True)
class WSObservation:
    """Raw, transport-level facts gathered from a single WS attempt."""
    connected: bool
    response: str | None = None
    close_code: int | None = None
    close_reason: str | None = None
    scheme: str = "ws"


def _is_jsonrpc_reply(text: str) -> bool:
    """True only for a JSON-RPC 2.0 reply shape (result/error), not any frame."""
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(obj, dict) and (
        obj.get("jsonrpc") == "2.0" or "result" in obj or "error" in obj
    )


def classify(obs: WSObservation, profile: OpenClawProfile | None = None) -> WSResult:
    """Pure mapping from observed signals to an outcome. No I/O."""
    profile = profile or load_profile()

    if not obs.connected:
        return WSResult.UNREACHABLE

    # A 1008 close, or any close/response carrying a fail-closed reason, means
    # auth is being enforced — exactly what we want OpenClaw to do.
    if obs.close_code is not None and profile.ws_close_codes.get(obs.close_code) == "fail_closed":
        return WSResult.FAIL_CLOSED
    if profile.is_fail_closed_reason(obs.close_reason):
        return WSResult.FAIL_CLOSED

    if obs.response is not None:
        if profile.is_fail_closed_reason(obs.response):
            return WSResult.FAIL_CLOSED
        # Only a JSON-RPC reply to our probe proves unauthenticated control.
        # Any other frame (a greeting, an echo, a chat banner) just means the
        # socket is open with unclear auth — not a CRITICAL bypass.
        if _is_jsonrpc_reply(obs.response):
            return WSResult.UNAUTH_RPC
        return WSResult.ACCEPTED_NO_RESPONSE

    if obs.close_code is not None:
        # Closed for some other reason without ever answering.
        return WSResult.ACCEPTED_NO_RESPONSE

    return WSResult.ACCEPTED_NO_RESPONSE


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _attempt(ws_url: str, rpc: str, use_tls: bool) -> WSObservation:
    scheme = "wss" if use_tls else "ws"
    kwargs = {"close_timeout": 3, "open_timeout": 3}
    if use_tls:
        kwargs["ssl"] = _ssl_context()

    try:
        async with websockets.connect(ws_url, **kwargs) as ws:
            try:
                # send + recv share the same handler: a gateway that closes
                # immediately (fail-closed) may raise ConnectionClosed on either.
                await ws.send(rpc)
                response = await asyncio.wait_for(ws.recv(), timeout=2)
                return WSObservation(connected=True, response=str(response), scheme=scheme)
            except asyncio.TimeoutError:
                return WSObservation(connected=True, scheme=scheme)
            except websockets.exceptions.ConnectionClosed as cc:
                return WSObservation(
                    connected=True,
                    close_code=cc.code,
                    close_reason=cc.reason,
                    scheme=scheme,
                )
    except _REFUSED_EXCEPTIONS:
        # Handshake refused (e.g. HTTP 401/403) == fail-closed auth.
        return WSObservation(connected=True, close_code=1008, close_reason="handshake refused", scheme=scheme)
    except Exception:
        return WSObservation(connected=False, scheme=scheme)


async def probe_ws(
    host: str,
    port: int,
    path: str = "/",
    prefer_tls: bool = False,
    profile: OpenClawProfile | None = None,
    evidence: EvidenceCollector | None = None,
) -> tuple[WSResult, WSObservation]:
    """Probe a gateway WebSocket over ws:// and wss://, return the strongest result."""
    profile = profile or load_profile()
    rpc = profile.ws_rpc_probe
    schemes = ["wss", "ws"] if prefer_tls else ["ws", "wss"]

    best: tuple[WSResult, WSObservation] | None = None
    for scheme in schemes:
        ws_url = f"{scheme}://{host}:{port}{path}"
        obs = await _attempt(ws_url, rpc, use_tls=scheme == "wss")
        result = classify(obs, profile)

        if obs.connected and evidence is not None and obs.response is not None:
            evidence.save_ws_response(ws_url, rpc, obs.response)

        if best is None or _rank(result) > _rank(best[0]):
            best = (result, obs)
        # An unauthenticated RPC response is the strongest possible signal.
        if result is WSResult.UNAUTH_RPC:
            break

    return best if best is not None else (WSResult.UNREACHABLE, WSObservation(connected=False))


_RANK = {
    WSResult.UNREACHABLE: 0,
    WSResult.FAIL_CLOSED: 1,
    WSResult.ACCEPTED_NO_RESPONSE: 2,
    WSResult.UNAUTH_RPC: 3,
}


def _rank(result: WSResult) -> int:
    return _RANK.get(result, 0)
