from __future__ import annotations

import asyncio
from typing import Optional

import aiohttp
import dns.exception
import dns.resolver

from subreaper.models import GhostIP

# ── Constants ─────────────────────────────────────────────────────────────────

_TCP_TIMEOUT  = 5
_HTTP_TIMEOUT = aiohttp.ClientTimeout(total=8)
_MAX_CONCURRENT_DNS   = 50  
_MAX_CONCURRENT_PROBE = 20

_ADMIN_SIGNALS   = ["phpmyadmin", "jenkins", "grafana", "kibana", "portainer", "traefik"]
_DEFAULT_SIGNALS = ["welcome to nginx", "apache2 ubuntu default page", "iis windows server"]
_ERROR_SIGNALS   = ["404 not found", "403 forbidden", "401 unauthorized"]


# ── Module-level async helpers (menghindari async @staticmethod) ──────────────

async def _tcp_alive(ip: str, timeout: float = _TCP_TIMEOUT) -> bool:
    for port in (80, 443):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            continue
    return False


async def _http_get(ip: str) -> tuple[int, str]:
    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}/"
        try:
            async with aiohttp.ClientSession(timeout=_HTTP_TIMEOUT) as session:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    body = await resp.text(errors="replace")
                    return resp.status, body[:500]
        except Exception:
            continue
    return 0, ""


def _resolve_a(hostname: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(hostname, "A")
        return sorted({r.to_text() for r in answers})
    except (dns.exception.DNSException, Exception):
        return []


# ── Detector ──────────────────────────────────────────────────────────────────

class GhostIPDetector:

    # ── Public entrypoint ─────────────────────────────────────────────────────

    async def detect(
        self,
        subdomains:  list[str],
        current_ips: list[str],
    ) -> list[GhostIP]:
        """
        Resolves subdomains, filters IPs already in current_ips,
        probes survivors, dan returns GhostIP entries sorted by priority.
        """
        candidates = await self._resolve_candidates(subdomains, set(current_ips))
        if not candidates:
            return []

        sem     = asyncio.Semaphore(_MAX_CONCURRENT_PROBE)
        tasks   = [self._probe_with_sem(sem, ip, via) for ip, via in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        ghosts = [
            g for g in results
            if isinstance(g, GhostIP) and g.status != "DEAD"
        ]
        ghosts.sort(key=lambda g: g.priority, reverse=True)
        return ghosts

    # ── Step 1: resolve → candidates ─────────────────────────────────────────

    async def _resolve_candidates(
        self,
        subdomains:  list[str],
        current_ips: set[str],
    ) -> list[tuple[str, str]]:
        """
        Returns (ip, subdomain) pairs.
        - IP tidak ada di current_ips
        - IP tidak duplikat (satu IP → satu subdomain, first-seen wins)
        - Konkurensi DNS dibatasi _MAX_CONCURRENT_DNS
        """
        sem       = asyncio.Semaphore(_MAX_CONCURRENT_DNS)
        loop      = asyncio.get_running_loop()
        seen_ips: set[str] = set()
        lock      = asyncio.Lock()
        result:   list[tuple[str, str]] = []

        async def _resolve_one(sub: str) -> None:
            async with sem:
                ips = await loop.run_in_executor(None, _resolve_a, sub)
            async with lock:
                for ip in ips:
                    if ip not in current_ips and ip not in seen_ips:
                        seen_ips.add(ip)
                        result.append((ip, sub))

        await asyncio.gather(*[_resolve_one(s) for s in subdomains])
        return result

    # ── Step 2: probe (dengan semaphore) ─────────────────────────────────────

    async def _probe_with_sem(
        self,
        sem: asyncio.Semaphore,
        ip:  str,
        via: str,
    ) -> GhostIP:
        async with sem:
            return await self._probe(ip, via)

    async def _probe(self, ip: str, via: str) -> GhostIP:
        ghost = GhostIP(ip=ip, via_subdomain=via, status="DEAD")

        if not await _tcp_alive(ip):
            return ghost

        http_status, body = await _http_get(ip)

        if http_status == 0 and not body:
            ghost.status    = "ALIVE_NO_HTTP"
            ghost.priority += 2
            return ghost

        body_lower = body.lower()

        ghost.status          = "ALIVE_WITH_HTTP"
        ghost.http_status     = http_status
        ghost.body_preview    = body[:200]
        ghost.has_admin_panel  = any(s in body_lower for s in _ADMIN_SIGNALS)
        ghost.has_default_page = any(s in body_lower for s in _DEFAULT_SIGNALS)
        ghost.has_error_page   = any(s in body_lower for s in _ERROR_SIGNALS)
        ghost.priority        += _score(ghost)
        return ghost


# ── Step 3: scoring (module-level, murni functional) ─────────────────────────

def _score(g: GhostIP) -> int:
    score = 0
    if g.has_admin_panel:
        score += 30
        if g.http_status in (200, 401, 403):
            score += 10  
    if g.has_default_page:
        score += 20
    if g.http_status == 200 and not g.has_admin_panel:
        score += 10
    if g.http_status in (401, 403) and not g.has_admin_panel:
        score += 5
    if g.has_error_page:
        score += 3       
    return score