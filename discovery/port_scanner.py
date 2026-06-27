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
    8642, 9119,   # Hermes Agent: API server + dashboard
    8080, 8000, 3000,
    80, 443,
]

# Less-common LLM-server ports, scanned only with --llm-ports (keeps the
# default scan fast). Verified service defaults: LM Studio 1234, Jan 1337,
# AnythingLLM 3001, GPT4All 4891, oobabooga 5000, Triton metrics 8002,
# TGI alt 9000, Xinference 9997.
LLM_EXTRA_PORTS = [1234, 1337, 3001, 4891, 5000, 8002, 9000, 9997]


@dataclass(frozen=True)
class PortResult:
    ip: str
    port: int
    open: bool
    banner: Optional[str] = None
    latency_ms: Optional[float] = None


async def scan_port(ip: str, port: int, timeout: float = 3.0) -> PortResult:
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
    except Exception:
        return PortResult(ip=ip, port=port, open=False)

    latency = (loop.time() - start) * 1000
    # No banner grab: every DEFAULT_PORTS service is HTTP and is fully
    # fingerprinted by probe_http; the write + up-to-1s read was pure idle cost.
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass  # a RST during teardown must not demote a confirmed-open port

    return PortResult(ip=ip, port=port, open=True, latency_ms=latency)


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
