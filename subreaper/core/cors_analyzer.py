from __future__ import annotations

import asyncio
import re
import ssl
from urllib.parse import urlparse

import aiohttp

from subreaper.data.cors_signals import (
    CORS_HEADERS,
    CORS_PROBE_PATHS,
    CORS_PROBE_VALID_STATUS,
    CORS_WILDCARD_VALUES,
)
from subreaper.data.waf_providers import CDN_HEADERS_SIGNALS, CDN_PRESENCE_HEADERS
from subreaper.data.http_signals import DEFAULT_HEADERS, PROVIDER_HEADER_PREFIXES
from subreaper.models import CorsChainResult, ScanResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def _origin_for(domain: str) -> str:
    """Return a well-formed https origin string for a domain."""
    return f"https://{domain}"


def _parse_host(value: str) -> str:
    """Extract hostname from an ACAO value; return '' on failure."""
    if not value:
        return ""
    if not _SCHEME_RE.match(value):
        value = f"https://{value}"
    try:
        return (urlparse(value).hostname or "").lower()
    except Exception:
        return ""


def _is_subdomain_of(host: str, parent: str) -> bool:
    host = host.lower().lstrip(".")
    parent = parent.lower().lstrip(".")
    return host == parent or host.endswith(f".{parent}")


def _is_cdn(headers) -> bool:
    check_headers = ("Server", "Via", "X-Cache", "X-Served-By", "X-CDN")
    for h in check_headers:
        val = headers.get(h, "").lower()
        if val and any(sig in val for sig in CDN_HEADERS_SIGNALS):
            return True
    header_keys = {k.lower() for k in headers.keys()}
    if any(
        any(key.startswith(prefix) for key in header_keys)
        for prefix in PROVIDER_HEADER_PREFIXES
    ):
        return True

    return False
# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------


class CorsAnalyzer:

    async def analyze(
        self,
        results: list[ScanResult],
    ) -> list[CorsChainResult]:
        dangerous = self._collect_dangerous(results)
        if not dangerous:
            return []

        clean = [r for r in results if r.status == "CLEAN"]
        if not clean:
            return []

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        timeout = aiohttp.ClientTimeout(total=8, connect=3)
        semaphore = asyncio.Semaphore(10)

        findings: list[CorsChainResult] = []

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=aiohttp.TCPConnector(ssl=ssl_ctx),
        ) as session:
            tasks = [
                self._probe_domain(r.domain, dangerous, session, ssl_ctx, semaphore)
                for r in clean
            ]
            for batch in await asyncio.gather(*tasks, return_exceptions=True):
                if isinstance(batch, list):
                    findings.extend(batch)

        return findings

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _collect_dangerous(results: list[ScanResult]) -> set[str]:
        dangerous: set[str] = set()
        for r in results:
            if r.status != "VULNERABLE":
                continue
            for v in r.vulnerabilities:
                if v.vuln_type in (
                    "DANGLING_CNAME",
                    "SUBDOMAIN_TAKEOVER",
                    "UNCLAIMED_PROVIDER_ACCOUNT",
                ):
                    dangerous.add(r.domain.lower())
        return dangerous

    async def _probe_domain(
        self,
        domain: str,
        dangerous: set[str],
        session: aiohttp.ClientSession,
        ssl_ctx: ssl.SSLContext,
        semaphore: asyncio.Semaphore,
    ) -> list[CorsChainResult]:
        async with semaphore:
            for scheme in ("https", "http"):
                base_url = f"{scheme}://{domain}"
                try:
                    # ── Phase 1: baseline probe (no Origin) ───────────────
                    async with session.get(
                        f"{base_url}/",
                        ssl=ssl_ctx,
                        allow_redirects=True,
                    ) as baseline:
                        if baseline.status not in CORS_PROBE_VALID_STATUS:
                            break
                        if _is_cdn(baseline.headers):
                            return []

                    # ── Phase 2: spoofed-Origin probes ────────────────────
                    findings: list[CorsChainResult] = []

                    for dangerous_domain in dangerous:
                        spoofed_origin = _origin_for(dangerous_domain)

                        for path in CORS_PROBE_PATHS:
                            result = await self._probe_one(
                                session,
                                ssl_ctx,
                                f"{base_url}{path}",
                                spoofed_origin,
                                domain,
                                dangerous_domain,
                            )
                            if result is not None:
                                findings.append(result)
                                break  
                    return findings

                except Exception:
                    continue

        return []

    @staticmethod
    async def _probe_one(
        session: aiohttp.ClientSession,
        ssl_ctx: ssl.SSLContext,
        url: str,
        spoofed_origin: str,
        domain: str,
        dangerous_domain: str,
    ) -> CorsChainResult | None:
        for method in ("GET", "OPTIONS"):
            try:
                request_headers = {
                    **DEFAULT_HEADERS,
                    "Origin": spoofed_origin,
                }
                if method == "OPTIONS":
                    request_headers["Access-Control-Request-Method"] = "GET"
                    request_headers["Access-Control-Request-Headers"] = "authorization,content-type"

                async with session.request(
                    method,
                    url,
                    ssl=ssl_ctx,
                    allow_redirects=False,
                    headers=request_headers,
                ) as resp:
                    valid_status = CORS_PROBE_VALID_STATUS | {204} 
                    if resp.status not in valid_status:
                        continue 

                    if _is_cdn(resp.headers):
                        return None

                    cors_value = resp.headers.get("Access-Control-Allow-Origin", "").strip()
                    if not cors_value or cors_value in CORS_WILDCARD_VALUES:
                        continue  

                    # Reflect test
                    if cors_value.rstrip("/").lower() != spoofed_origin.rstrip("/").lower():
                        continue

                    origin_host = _parse_host(cors_value)
                    if not origin_host:
                        continue

                    if not _is_subdomain_of(origin_host, dangerous_domain):
                        continue

                    credentials = (
                        resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
                        == "true"
                    )

                    severity   = "CRITICAL" if credentials else "HIGH"
                    vuln_type  = "CORS_CHAIN_CREDENTIALS" if credentials else "CORS_CHAIN"
                    probe_note = f" [via {method}]" 

                    recommendation = (
                        f"Remove or restrict Access-Control-Allow-Origin on {domain}. "
                        f"The whitelisted origin '{cors_value}' is vulnerable to takeover "
                        f"via '{dangerous_domain}'."
                    )
                    if credentials:
                        recommendation += (
                            " Immediately revoke Access-Control-Allow-Credentials: true — "
                            "this allows an attacker to exfiltrate authenticated session data."
                        )

                    return CorsChainResult(
                        affected_domain=domain,
                        dangerous_origin=dangerous_domain,
                        cors_value=cors_value,
                        credentials=credentials,
                        vuln_type=vuln_type,
                        severity=severity,
                        recommendation=recommendation,
                    )

            except Exception:
                continue

        return None
