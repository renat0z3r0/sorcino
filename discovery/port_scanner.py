from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Optional


DEFAULT_PORTS = [
    18789,
    18791,
    18793,
    11434,
    4000,
    8080, 8000, 3000,
    80, 443,
]


@dataclass(frozen=True)
class PortResult:
    ip: str
    port: int
    open: bool
    banner: Optional[str] = None
    latency_ms: Optional[float] = None


async def scan_port(ip: str, port: int, timeout: float = 3.0) -> PortResult:
    start = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        latency = (asyncio.get_event_loop().time() - start) * 1000

        banner = None
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = data.decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            pass

        writer.close()
        await writer.wait_closed()

        return PortResult(ip=ip, port=port, open=True, banner=banner, latency_ms=latency)
    except Exception:
        return PortResult(ip=ip, port=port, open=False)


async def scan_host(
    ip: str,
    ports: list[int] | None = None,
    concurrency: int = 20,
    timeout: float = 3.0,
) -> list[PortResult]:
    if ports is None:
        ports = DEFAULT_PORTS

    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_scan(port: int) -> PortResult:
        async with semaphore:
            return await scan_port(ip, port, timeout)

    tasks = [bounded_scan(p) for p in ports]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r.open]
