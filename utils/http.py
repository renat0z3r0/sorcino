from __future__ import annotations

import aiohttp

# A hostile or misconfigured target can return an unbounded body; resp.text()
# would buffer all of it and can OOM the scanner. Cap every read.
MAX_BODY_BYTES = 65536


async def read_capped(resp: aiohttp.ClientResponse, limit: int = MAX_BODY_BYTES) -> str:
    raw = await resp.content.read(limit)
    return raw.decode(resp.charset or "utf-8", errors="ignore")
