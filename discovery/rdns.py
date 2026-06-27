from __future__ import annotations

import asyncio
import socket


async def reverse_dns(ip: str) -> str | None:
    """Resolve PTR record for an IP. Returns hostname or None."""
    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=3.0,
        )
        return result[0]
    except Exception:
        return None


async def reverse_dns_bulk(
    ips: list[str],
    concurrency: int = 20,
) -> dict[str, str | None]:
    """Resolve PTR records for multiple IPs concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, str | None] = {}

    async def _resolve(ip: str) -> None:
        async with semaphore:
            results[ip] = await reverse_dns(ip)

    await asyncio.gather(*[_resolve(ip) for ip in set(ips)])
    return results
