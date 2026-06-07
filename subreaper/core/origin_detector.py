from __future__ import annotations

import re
import asyncio
import aiohttp
import ssl as ssl_module
from dataclasses import dataclass, field
from ipaddress import AddressValueError, ip_address, ip_network

import dns.exception
import dns.resolver
import dns.reversename

from subreaper.data.waf_providers import CDN_PROVIDERS, CdnProvider, CDN_BODY_SIGNALS, CDN_SERVER_HEADERS, ANYCAST_BLOCKS, PUBLIC_RESOLVERS
from subreaper.models import IpPath



# ── Detector ──────────────────────────────────────────────────────────────────

class OriginDetector:

    def __init__(self) -> None:
        self._resolve_cache: dict[str, list[str]] = {}
    # ── Public entrypoint ─────────────────────────────────────────────────────

    async def detect(
        self,
        domain:   str,
        dns_info,
        validate: bool = False,
    ) -> tuple[list[str], list[IpPath], bool]:
        waf_detected = self._detect_waf(dns_info)

        if not waf_detected and not validate:
            return [], [], False

        ip_paths     = self._collect_ip_paths(domain, dns_info)
        waf_ranges   = self._collect_waf_ranges(waf_detected) if waf_detected else []
        origin_ips   = self._filter_origins(ip_paths, waf_ranges, dns_info, domain)
        if validate and origin_ips:
            origin_ips = await self._validate_origin_ips(origin_ips, domain)
        bypassable   = bool(origin_ips)

        return waf_detected, origin_ips, bypassable

    # ── Step 1: WAF detection ─────────────────────────────────────────────────

    def _detect_waf(self, dns_info) -> list[str]:
        detected: list[str] = []

        for ns_entry in (dns_info.ns_records or []):
            for name, cfg in CDN_PROVIDERS.items():
                if name not in detected and self._matches_any(ns_entry, cfg.ns_patterns):
                    detected.append(name)

        for hop in (dns_info.cname_chain or []):
            target = hop.get("to", "") if isinstance(hop, dict) else getattr(hop, "to", "")
            for name, cfg in CDN_PROVIDERS.items():
                if name not in detected and self._matches_any(target, cfg.cname_patterns):
                    detected.append(name)

        for ip in (dns_info.a_records or []):
            for name, cfg in CDN_PROVIDERS.items():
                if name not in detected and self._in_waf_range(ip, cfg.ip_ranges):
                    if not self._is_shared_cdn_ip(ip):
                        detected.append(name)

        return detected

    # ── Step 2: IP path collection ────────────────────────────────────────────

    def _collect_ip_paths(self, domain: str, dns_info) -> list[IpPath]:
        paths: list[IpPath] = []

        for ip in (dns_info.a_records or []):
            paths.append(IpPath(
                source="A_RECORD",
                via=domain,
                ip=ip,
                label="Direct A record",
            ))
        for ip in (dns_info.aaaa_records or []):
            paths.append(IpPath(
                source="AAAA_RECORD",
                via=domain,
                ip=ip,
                label="Direct AAAA record",
            ))

        for hop in (dns_info.cname_chain or []):
            if isinstance(hop, dict):
                target   = hop.get("to", "")
                dangling = hop.get("dangling", False)
            else:
                target   = getattr(hop, "to", "")
                dangling = getattr(hop, "dangling", False)

            if dangling or not target:
                continue

            for ip in self._resolve_a(target):
                paths.append(IpPath(
                    source="CNAME_CHAIN",
                    via=target,
                    ip=ip,
                    label=f"CNAME chain: {domain} → {target}",
                ))

        for ns in (dns_info.ns_records or []):
            clean = ns.rstrip(".")
            for ip in self._resolve_a(clean):
                paths.append(IpPath(
                    source="NS_SERVER",
                    via=clean,
                    ip=ip,
                    label=f"NS server: {clean}",
                ))

        for mx in (dns_info.mx_records or []):
            clean = mx.rstrip(".")
            for ip in self._resolve_a(clean):
                paths.append(IpPath(
                    source="MX_SERVER",
                    via=clean,
                    ip=ip,
                    label=f"MX server: {clean}",
                ))

        for txt in (dns_info.txt_records or []):
            if not txt.startswith("v=spf1"):
                continue
            for cidr in re.findall(r"ip[46]:([^\s]+)", txt):
                paths.append(IpPath(
                    source="SPF_RECORD",
                    via="SPF include",
                    ip=cidr,
                    label=f"SPF: {cidr}",
                    is_range=True,
                ))

        return paths

    # ── Step 3: Filter non-WAF IPs ────────────────────────────────────────────

    def _collect_waf_ranges(self, detected: list[str]) -> list[str]:
        ranges: list[str] = []
        for name in detected:
            cfg = CDN_PROVIDERS.get(name)
            if cfg:
                ranges.extend(cfg.ip_ranges)
        return ranges

    def _filter_origins(
        self,
        ip_paths:   list[IpPath],
        waf_ranges: list[str],
        dns_info=None,
        domain: str = "",
    ) -> list[IpPath]:
        merged: dict[str, IpPath] = {}
        mx_empty = not (dns_info.mx_records if dns_info else None)
        for path in ip_paths:
            if path.is_range:
                if path.source == "SPF_RECORD" and not mx_empty:
                    continue
                if path.source != "SPF_RECORD":
                    continue
                try:
                    net = ip_network(path.ip, strict=False)
                    if net.prefixlen not in (32, 128):
                        continue
                    path = IpPath(
                        source=path.source,
                        via=path.via,
                        ip=str(net.network_address),
                        label=path.label,
                        is_range=False,
                    )
                except ValueError:
                    continue
            if path.source == "NS_SERVER":     
                continue
            if "dangling" in path.label.lower(): 
                continue
            if self._is_shared_cdn_ip(path.ip): 
                continue
            if self._in_waf_range(path.ip, waf_ranges):
                if not self._ptr_matches_domain(path.ip, domain):
                    continue
                path = IpPath(
                    source=path.source,
                    via=path.via,
                    ip=path.ip,
                    label=f"{path.label} [PTR rescued]",
                )
            if self._is_anycast_ip(path.ip):
                continue
            if path.ip in merged:
                existing = merged[path.ip]
                if path.source not in existing.source:
                    merged[path.ip] = IpPath(
                        source=f"{existing.source}, {path.source}",
                        via=existing.via,
                        ip=existing.ip,
                        label=existing.label,
                    )
            else:
                merged[path.ip] = path

        return list(merged.values())

    def _is_shared_cdn_ip(self, ip_str: str) -> bool:
        match_count = sum(
            1 for cfg in CDN_PROVIDERS.values()
            if self._in_waf_range(ip_str, cfg.ip_ranges)
        )
        return match_count > 3

    def _is_anycast_ip(self, ip_str: str) -> bool:
        return self._in_waf_range(ip_str, ANYCAST_BLOCKS)

    @staticmethod
    def _ptr_matches_domain(ip_str: str, domain: str) -> bool:
        try:
            reversed_name = dns.reversename.from_address(ip_str)
            answers = dns.resolver.resolve(reversed_name, "PTR", lifetime=2)
            root = domain.lstrip("www.").lower()
            for rdata in answers:
                ptr = rdata.to_text().rstrip(".").lower()
                if root in ptr:
                    return True
        except Exception:
            pass
        return False

    async def _validate_origin_ips(
        self,
        candidates: list[IpPath],
        domain:     str,
    ) -> list[IpPath]:
        ssl_ctx = ssl_module.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl_module.CERT_NONE

        timeout = aiohttp.ClientTimeout(total=5, connect=3)

        baseline_body: str = ""
        try:
            async with aiohttp.ClientSession(timeout=timeout) as s:
                async with s.get(f"https://{domain}/", ssl=ssl_ctx, allow_redirects=False) as r:
                    baseline_body = (await r.content.read(65536)).decode(errors="ignore").lower()
        except Exception:
            pass
            
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=aiohttp.TCPConnector(ssl=ssl_ctx),
        ) as shared_session:
            async def _probe(path: IpPath) -> IpPath | None:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{path.ip}/"
                    try:
                        async with shared_session.get(
                            url,
                            headers={"Host": domain},
                            ssl=ssl_ctx,
                            allow_redirects=False,
                        ) as resp:
                            if resp.status >= 400:
                                return None
                            if resp.status in (301, 302, 307, 308):
                                location = resp.headers.get("Location", "")
                                if location.startswith("http") and domain not in location:
                                    return None
                            server_header = resp.headers.get("Server", "").lower()
                            if any(sig in server_header for sig in CDN_SERVER_HEADERS):
                                return None
                            body = (await resp.content.read(65536)).decode(errors="ignore").lower()
                            if any(sig in body for sig in CDN_BODY_SIGNALS):
                                return None
                            if baseline_body and body:
                                common = len(set(body.split()) & set(baseline_body.split()))
                                similarity = common / max(len(baseline_body.split()), 1)
                                if similarity < 0.3:
                                    return None
                            return path
                    except Exception:
                        continue
                return None

            semaphore = asyncio.Semaphore(5)
            async def _rate_limited_probe(path: IpPath) -> IpPath | None:
                async with semaphore:
                    return await _probe(path)

            results = await asyncio.gather(*[_rate_limited_probe(p) for p in candidates])

        return [r for r in results if r is not None]
    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _matches_any(value: str, patterns: list[str]) -> bool:
        return any(re.search(pat, value, re.IGNORECASE) for pat in patterns)

    def _resolve_a(self, hostname: str) -> list[str]:
        if hostname in self._resolve_cache:
            return self._resolve_cache[hostname]

        all_ips: set[str] = set()

        for ns in PUBLIC_RESOLVERS:
            try:
                r = dns.resolver.Resolver()
                r.nameservers = [ns]
                r.timeout  = 2
                r.lifetime = 2
                for rtype in ("A", "AAAA"):
                    try:
                        answers = r.resolve(hostname, rtype)
                        all_ips.update(rec.to_text() for rec in answers)
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        pass
                    except dns.exception.DNSException:
                        pass
            except Exception:
                continue

        result = sorted(all_ips)
        self._resolve_cache[hostname] = result
        return result

    @staticmethod
    def _in_waf_range(ip_str: str, ranges: list[str]) -> bool:
        try:
            addr = ip_address(ip_str)
            return any(addr in ip_network(cidr, strict=False) for cidr in ranges)
        except (AddressValueError, ValueError):
            return False