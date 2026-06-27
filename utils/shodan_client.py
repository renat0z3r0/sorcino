from __future__ import annotations
import aiohttp


async def fetch_shodan_targets(
    api_key: str,
    query: str,
    limit: int = 1000,
) -> list[dict]:
    targets: list[dict] = []

    async with aiohttp.ClientSession() as session:
        page = 1
        while len(targets) < limit:
            params = {"key": api_key, "query": query, "page": page}

            try:
                async with session.get(
                    "https://api.shodan.io/shodan/host/search",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 401:
                        raise ValueError("Invalid Shodan API key")
                    if resp.status == 402:
                        raise ValueError("Shodan query credits exhausted")
                    if resp.status != 200:
                        break

                    data = await resp.json()
                    matches = data.get("matches", [])

                    if not matches:
                        break

                    for match in matches:
                        targets.append({
                            "ip": match.get("ip_str"),
                            "port": match.get("port"),
                            "org": match.get("org"),
                            "country": match.get("location", {}).get("country_code"),
                            "hostnames": match.get("hostnames", []),
                            "data": match.get("data", "")[:500],
                            "timestamp": match.get("timestamp"),
                        })
                        if len(targets) >= limit:
                            break

                    page += 1

            except aiohttp.ClientError:
                break

    return targets
