from __future__ import annotations
import asyncio
import aiohttp
from dataclasses import dataclass
from typing import Optional

from utils.http import read_capped


DEFAULT_PATHS = [
    "/",
    "/health",
    "/healthz",
    "/status",
    "/api",
    "/api/health",
    "/v1",
    "/v1/models",
    "/v1/chat/completions",
    "/metrics",
    "/.env",
    "/config",
    "/admin",
    "/debug",
    "/webchat",
    "/dashboard",
    "/api/config",
]


@dataclass(frozen=True)
class HTTPProbeResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body_preview: str
    content_type: Optional[str]
    server_header: Optional[str]
    response_time_ms: float
    is_json: bool
    is_html: bool
    redirect_url: Optional[str] = None


async def _probe_with_session(
    session: aiohttp.ClientSession,
    ip: str,
    port: int,
    paths: list[str],
) -> list[HTTPProbeResult]:
    results: list[HTTPProbeResult] = []
    schemes = ["https", "http"] if port in (443, 8443) else ["http", "https"]

    for scheme in schemes:
        base_url = f"{scheme}://{ip}:{port}"

        for path in paths:
            url = f"{base_url}{path}"
            try:
                start = asyncio.get_running_loop().time()
                async with session.get(url, allow_redirects=False) as resp:
                    elapsed = (asyncio.get_running_loop().time() - start) * 1000
                    body = await read_capped(resp)
                    ct = resp.headers.get("Content-Type", "")

                    results.append(HTTPProbeResult(
                        url=url,
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body_preview=body[:2048],
                        content_type=ct,
                        server_header=resp.headers.get("Server"),
                        response_time_ms=elapsed,
                        is_json="application/json" in ct,
                        is_html="text/html" in ct,
                        redirect_url=resp.headers.get("Location"),
                    ))
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue

        # Once a scheme answered, don't waste time on the other one (the old
        # code only short-circuited for port 443, so every plain-HTTP port paid
        # a full round of https timeouts).
        if results:
            break

    return results


async def probe_http(
    ip: str,
    port: int,
    paths: list[str] | None = None,
    timeout: float = 10.0,
    session: aiohttp.ClientSession | None = None,
) -> list[HTTPProbeResult]:
    if paths is None:
        paths = DEFAULT_PATHS

    # Reuse the caller's session when provided (connection pooling); otherwise
    # manage a short-lived one.
    if session is not None:
        return await _probe_with_session(session, ip, port, paths)

    connector = aiohttp.TCPConnector(ssl=False)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as own:
        return await _probe_with_session(own, ip, port, paths)
