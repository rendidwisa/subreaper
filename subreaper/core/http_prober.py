"""
HTTP Prober for SubReaper.

Probes a domain over HTTPS then HTTP, reads a body slice for fingerprinting,
and returns a normalised result dict consumed by VulnDetector._probe_http().
"""

from __future__ import annotations

import asyncio
import re
from typing import Optional

import aiohttp
import ssl as ssl_module

from subreaper.data.http_signals import (
    PROVIDER_HEADER_PREFIXES,
    DEFAULT_HEADERS,
    BARE_ERROR_PATTERNS,
)

# ── Constants ─────────────────────────────────────────────────────────────────
_BODY_LIMIT = 8_000

_SCHEMES = ("https", "http")

_MAX_REDIRECTS = 5
_MAX_RETRIES   = 3
_BACKOFF_BASE  = 1.5  

# ── HTTPProber ────────────────────────────────────────────────────────────────

class HTTPProber:
    """
    Minimal HTTP prober whose only job is to return enough signal for
    VulnDetector to run fingerprint matching.

    Return schema (always a dict):
        status          int     HTTP status code
        url             str     Final URL after redirects
        body            str     First _BODY_LIMIT chars of response body
        headers         dict    All response headers (lowercased keys)
        provider_headers dict   Subset of headers with provider signal
        ssl_error       bool    True when HTTPS succeeded but TLS layer warned
        scheme          str     "https" or "http" — whichever succeeded
        error           str     Present only on complete failure
    """

    def __init__(self, timeout: int = 10):
        self._timeout = aiohttp.ClientTimeout(
            total=timeout,
            connect=min(timeout, 5),   # don't burn the whole budget on TCP
        )

    # ── Public API ────────────────────────────────────────────────────────────

    async def probe(
        self,
        domain: str,
        custom_host: Optional[str] = None,
        use_default_headers: bool = True,
        extra_headers: Optional[dict] = None,
    ) -> dict:
        """
        Probe *domain* and return a result dict.

        custom_host: override the Host header.
        use_default_headers: if False, only send minimal headers (just Host if custom_host given).
        extra_headers: additional headers to include in the request.
        """
        headers = DEFAULT_HEADERS.copy() if use_default_headers else {}
        if custom_host:
            headers["Host"] = custom_host
        if extra_headers:
            headers.update(extra_headers)

        ssl_context = ssl_module.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl_module.CERT_NONE

        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=10,              # per-prober limit; caller controls concurrency
            enable_cleanup_closed=True,
        )

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self._timeout,
            # No cookie jar — we don't want session state between retries
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as session:
            for scheme in _SCHEMES:
                url = f"{scheme}://{domain}"
                result = await self._request(url, headers, session, scheme)
                if "error" not in result:
                    return result

        return {"error": "all_schemes_failed"}

    # ── Internal request with retry ───────────────────────────────────────────

    async def _request(
        self,
        url:     str,
        headers: dict,
        session: aiohttp.ClientSession,
        scheme:  str,
    ) -> dict:
        last_error: str = "unknown"

        for attempt in range(_MAX_RETRIES):
            try:
                async with session.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    max_redirects=_MAX_REDIRECTS,
                ) as resp:
                    body = await self._read_body(resp)
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}

                    provider_headers = {
                        k: v
                        for k, v in resp_headers.items()
                        if any(k.startswith(p) for p in PROVIDER_HEADER_PREFIXES)
                    }

                    return {
                        "status":           resp.status,
                        "url":              str(resp.url),
                        "body":             body,
                        "headers":          resp_headers,
                        "provider_headers": provider_headers,
                        "ssl_error":        False,
                        "scheme":           scheme,
                        "classification":   self._classify(resp.status, body, resp_headers),
                    }

            except aiohttp.ServerFingerprintMismatch:
                # TLS server presented a cert that doesn't match the hostname —
                last_error = "ssl_fingerprint_mismatch"
                break

            except aiohttp.ClientSSLError as exc:
                # SSL protocol error at the aiohttp/OpenSSL layer — distinct from
                last_error = f"ssl_error:{type(exc).__name__}"
                break

            except aiohttp.ClientConnectorError as exc:
                # Connection refused, DNS failure for the URL host, etc.
                last_error = f"connector:{type(exc).__name__}"
                if attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(_BACKOFF_BASE ** attempt)

            except asyncio.TimeoutError:
                last_error = "timeout"
                if attempt < _MAX_RETRIES - 1:
                    await asyncio.sleep(_BACKOFF_BASE ** attempt)

            except aiohttp.TooManyRedirects:
                # Redirect loop — not worth retrying
                last_error = "too_many_redirects"
                break

            except aiohttp.ClientResponseError as exc:
                last_error = f"response_error:{exc.status}"
                break

            except Exception as exc:
                last_error = f"unexpected:{type(exc).__name__}:{str(exc)[:60]}"
                break

        return {"error": last_error}

    # ── Body reader ───────────────────────────────────────────────────────────

    @staticmethod
    async def _read_body(resp: aiohttp.ClientResponse) -> str:
        """
        Read up to _BODY_LIMIT characters.  Never raises — returns "" on error.
        """
        try:
            raw = await resp.content.read(_BODY_LIMIT)
            # Decode with replacement so binary / broken encodings don't crash us
            return raw.decode(resp.charset or "utf-8", errors="replace")
        except Exception:
            return ""

    # ── Response classifier ───────────────────────────────────────────────────

    @staticmethod
    def _classify(status: int, body: str, headers: dict) -> str:

        if status in {301, 302, 303, 307, 308}:
            return "REDIRECT"

        if status in {500, 502, 503, 504}:
            return "ERROR_PAGE"

        body_short = body[:500]

        has_provider_headers = any(
            k.startswith(p)
            for k in headers
            for p in PROVIDER_HEADER_PREFIXES
        )

        is_bare_404 = (
            len(body) < 300
            or any(p.search(body_short) for p in BARE_ERROR_PATTERNS)
        )

        # ── 404 LOGIC ─────────────────────────────
        if status == 404:
            if has_provider_headers:
                return "POTENTIAL_TAKEOVER"

            if is_bare_404:
                return "GENERIC_404"

            return "CUSTOM_404"

        # ── 200 LOGIC ─────────────────────────────
        if status == 200:

            if len(body.strip()) < 300:
                if has_provider_headers:
                    return "SUSPICIOUS_EMPTY_PAGE"
                return "EMPTY_PAGE"

            return "REAL_APP"

        return "UNKNOWN"