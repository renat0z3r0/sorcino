from __future__ import annotations
import aiohttp
from typing import Optional


async def resolve_asn_prefixes(asn: str) -> list[str]:
    prefixes: list[str] = []

    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for prefix in data.get("data", {}).get("ipv4_prefixes", []):
                        prefixes.append(prefix["prefix"])
                    if prefixes:
                        return prefixes
    except Exception:
        pass

    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for prefix in data.get("data", {}).get("prefixes", []):
                        if ":" not in prefix["prefix"]:
                            prefixes.append(prefix["prefix"])
    except Exception:
        pass

    return prefixes


async def get_asn_info(asn: str) -> Optional[dict]:
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://api.bgpview.io/asn/{asn}"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    d = data.get("data", {})
                    return {
                        "asn": asn,
                        "name": d.get("name"),
                        "description": d.get("description_short"),
                        "country": d.get("country_code"),
                    }
    except Exception:
        pass
    return None
