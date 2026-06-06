from __future__ import annotations

import json
import os
import asyncio
import aiohttp
import ssl as ssl_module

CACHE_PATH = os.path.expanduser("~/.subreaper/waf_ranges.json")

async def fetch_cloudfront_ips(session: aiohttp.ClientSession) -> list[str]:
    url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    async with session.get(url) as resp:
        data = await resp.json()
    prefixes = [p for p in data.get("prefixes", []) if p.get("service") == "CLOUDFRONT"]
    return [p["ip_prefix"] for p in prefixes]

async def fetch_cloudflare_ips(session: aiohttp.ClientSession) -> list[str]:
    urls = [
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ]
    ranges = []
    for url in urls:
        async with session.get(url) as resp:
            text = await resp.text()
            ranges.extend([line.strip() for line in text.splitlines() if line.strip()])
    return ranges

async def fetch_fastly_ips(session: aiohttp.ClientSession) -> list[str]:
    url = "https://api.fastly.com/public-ip-list"
    async with session.get(url) as resp:
        data = await resp.json()
    return data.get("addresses", [])

async def update_cache():
    ssl_ctx = ssl_module.create_default_context()
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=ssl_ctx)) as session:
        cloudfront = await fetch_cloudfront_ips(session)
        cloudflare = await fetch_cloudflare_ips(session)
        fastly = await fetch_fastly_ips(session)

    cache = {}
    if cloudfront:
        cache["CloudFront"] = cloudfront
    if cloudflare:
        cache["Cloudflare"] = cloudflare
    if fastly:
        cache["Fastly"] = fastly

    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w") as f:
        json.dump(cache, f, indent=2)

    print(f"WAF database updated. Cache saved to {CACHE_PATH}")