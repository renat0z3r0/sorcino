from __future__ import annotations
import asyncio
import aiohttp
from dataclasses import dataclass
from typing import Optional


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


async def probe_http(
    ip: str,
    port: int,
    paths: list[str] | None = None,
    timeout: float = 10.0,
) -> list[HTTPProbeResult]:
    if paths is None:
        paths = DEFAULT_PATHS

    results = []
    schemes = ["https", "http"] if port in (443, 8443) else ["http", "https"]

    connector = aiohttp.TCPConnector(ssl=False)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    async with aiohttp.ClientSession(
        timeout=client_timeout,
        connector=connector,
    ) as session:
        for scheme in schemes:
            base_url = f"{scheme}://{ip}:{port}"

            for path in paths:
                url = f"{base_url}{path}"
                try:
                    start = asyncio.get_event_loop().time()
                    async with session.get(url, allow_redirects=False) as resp:
                        elapsed = (asyncio.get_event_loop().time() - start) * 1000
                        body = await resp.text()
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

            if results and schemes[0] == "https":
                break

    return results
