"""
Async HTTP probing module.

Tries HTTPS first, falls back to HTTP.  Returns the first successful response
body and status code, up to BODY_READ_LIMIT bytes.
"""

import asyncio

import aiohttp


class HTTPProber:
    """
    Lightweight async HTTP prober.

    Usage::

        prober = HTTPProber(timeout=10)
        result = await prober.probe("sub.example.com")
        print(result["status"], result["body"][:200])
    """

    BODY_READ_LIMIT = 5_000   # bytes
    MAX_REDIRECTS   = 5
    SCHEMES         = ["https", "http"]

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; SubReaper/1.1; Bug-Bounty-Scanner)"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        ),
    }

    def __init__(self, timeout: int = 10):
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def probe(self, domain: str) -> dict:
        """
        Probe *domain* over HTTPS then HTTP (first success wins).

        Returns a dict with keys:
            status  (int)   — HTTP status code
            url     (str)   — final URL after redirects
            body    (str)   — first BODY_READ_LIMIT bytes of response body
            headers (dict)  — response headers

        On connection failure returns:
            {"error": str}
        """
        connector = aiohttp.TCPConnector(ssl=False, limit=50)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=self.DEFAULT_HEADERS,
        ) as session:
            for scheme in self.SCHEMES:
                url = f"{scheme}://{domain}"
                try:
                    async with session.get(
                        url,
                        allow_redirects=True,
                        max_redirects=self.MAX_REDIRECTS,
                    ) as resp:
                        body = ""
                        try:
                            body = await resp.text(errors="replace")
                            body = body[: self.BODY_READ_LIMIT]
                        except Exception:
                            pass

                        return {
                            "status":  resp.status,
                            "url":     str(resp.url),
                            "body":    body,
                            "headers": dict(resp.headers),
                        }

                except aiohttp.ClientConnectorError:
                    # Port closed / refused — try next scheme
                    continue
                except asyncio.TimeoutError:
                    return {"error": "timeout"}
                except Exception as exc:
                    return {"error": str(exc)[:100]}

        return {"error": "connection_refused"}