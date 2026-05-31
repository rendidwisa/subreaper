import asyncio
import aiohttp
from typing import Optional


class HTTPProber:
    BODY_READ_LIMIT = 5_000
    MAX_REDIRECTS = 5
    SCHEMES = ["https", "http"]
    MAX_RETRIES = 3
    BACKOFF_BASE = 1.5

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; SubReaper/1.2; +https://github.com/rendidwisa/subreaper)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    CLOUD_HEADER_PREFIXES = {"server", "x-amz-", "x-powered-by", "x-azure-", "x-fastly-", "x-vercel-"}

    def __init__(self, timeout: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    def _normalize(self, body: str) -> str:
        return body.strip().lower()

    def _classify(self, status: int, body: str, headers: dict) -> str:
        body_lower = body[:500].lower()
        if any(k.lower().startswith("x-") or k.lower() in {"server", "via"} for k in headers):
            return "GENERIC_CLOUD_PAGE"
        if status in {401, 403, 500, 502, 503}:
            return "ERROR_PAGE"
        if status == 200 and len(body) > 100:
            return "REAL_APP"
        if status == 404 and len(body) < 200:
            return "GENERIC_CLOUD_PAGE"
        return "REAL_APP"

    async def _request(self, url: str, headers: dict, session: aiohttp.ClientSession) -> dict:
        for attempt in range(self.MAX_RETRIES):
            try:
                async with session.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    max_redirects=self.MAX_REDIRECTS,
                ) as resp:
                    body = ""
                    try:
                        raw = await resp.text(errors="replace")
                        body = raw[:self.BODY_READ_LIMIT]
                    except Exception:
                        pass

                    resp_headers = dict(resp.headers)
                    cloud_headers = {
                        k: v for k, v in resp_headers.items()
                        if any(k.lower().startswith(p) for p in self.CLOUD_HEADER_PREFIXES)
                    }

                    return {
                        "status": resp.status,
                        "url": str(resp.url),
                        "body": body,
                        "headers": resp_headers,
                        "cloud_headers": cloud_headers,
                        "classification": self._classify(resp.status, body, resp_headers),
                    }
            except (aiohttp.ClientConnectorError, asyncio.TimeoutError):
                if attempt == self.MAX_RETRIES - 1:
                    return {"error": "timeout" if isinstance(asyncio.TimeoutError, type(None)) else "connection_refused"}
                await asyncio.sleep(self.BACKOFF_BASE ** attempt)
            except Exception as e:
                return {"error": str(e)[:100]}
        return {"error": "max_retries_exceeded"}

    async def probe(self, domain: str, custom_host: Optional[str] = None) -> dict:
        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        headers = self.DEFAULT_HEADERS.copy()
        if custom_host:
            headers["Host"] = custom_host

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
        ) as session:
            for scheme in self.SCHEMES:
                url = f"{scheme}://{domain}"
                result = await self._request(url, headers, session)
                if "error" not in result:
                    return result
        return {"error": "connection_refused"}