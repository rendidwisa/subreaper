from __future__ import annotations

import asyncio
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address, ip_network, AddressValueError

import dns.exception
import dns.resolver
import dns.reversename

from subreaper.models import DNSInfo, StaleDnsResult
from subreaper.data.stale_dns_signals import (
    CLOUD_IP_RANGES,
    TXT_VENDOR_PATTERNS,
    MX_ZOMBIE_SEVERITY,
    ZOMBIE_A_PTR_MISMATCH_SEVERITY,
    ZOMBIE_A_NO_PTR_SEVERITY,
)

_executor = ThreadPoolExecutor(max_workers=8)


class StaleDnsDetector:

    async def detect(self, domain: str, dns_info: DNSInfo) -> list[StaleDnsResult]:
        results: list[StaleDnsResult] = []
        tasks = [
            self._check_zombie_a(domain, dns_info),
            self._check_zombie_mx(domain, dns_info),
            self._check_zombie_txt(domain, dns_info),
        ]
        for findings in await asyncio.gather(*tasks):
            results.extend(findings)
        return results

    # ── Scenario A: Zombie A record ───────────────────────────────────────────

    async def _check_zombie_a(self, domain: str, dns_info: DNSInfo) -> list[StaleDnsResult]:
        results: list[StaleDnsResult] = []
        for ip_str in (dns_info.a_records or []):
            cloud_owner = self._in_cloud_range(ip_str)
            if not cloud_owner:
                continue
            if self._in_cdn_range(ip_str):
                continue
            ptr = await self._resolve_ptr(ip_str)
            apex = domain.removeprefix("www.") 
            if ptr and apex in ptr:
                continue
            severity = ZOMBIE_A_PTR_MISMATCH_SEVERITY if ptr else ZOMBIE_A_NO_PTR_SEVERITY
            reason = (
                f"IP {ip_str} is in {cloud_owner} range but PTR points to '{ptr}', not {domain}"
                if ptr else
                f"IP {ip_str} is in {cloud_owner} range with no reverse DNS"
            )
            results.append(StaleDnsResult(
                domain=domain,
                scenario="ZOMBIE_A",
                record_type="A",
                record_value=ip_str,
                reason=reason,
                severity=severity,
                recommendation=(
                    "Verify this IP is still owned by your organization. "
                    "If released back to the cloud provider, remove the A record immediately."
                ),
                ip_owner_info=cloud_owner,
                ip_is_cloud=True,
                ip_reverse_dns=ptr,
            ))
        return results

    # ── Scenario B: Zombie MX ─────────────────────────────────────────────────

    async def _check_zombie_mx(self, domain: str, dns_info: DNSInfo) -> list[StaleDnsResult]:
        results: list[StaleDnsResult] = []
        loop = asyncio.get_running_loop()
        for mx in (dns_info.mx_records or []):
            mx_host = mx.rstrip(".")
            try:
                priority = None
                if " " in mx_host:
                    parts = mx_host.split()
                    priority = int(parts[0])
                    mx_host  = parts[1].rstrip(".")
                resolvable = await asyncio.wait_for(
                    loop.run_in_executor(_executor, self._resolves, mx_host),
                    timeout=5,
                )
                if not resolvable:
                    results.append(StaleDnsResult(
                        domain=domain,
                        scenario="ZOMBIE_MX",
                        record_type="MX",
                        record_value=mx_host,
                        reason=f"MX record {mx_host} does not resolve — potential email interception",
                        severity=MX_ZOMBIE_SEVERITY,
                        recommendation=(
                            "Remove or update the MX record. "
                            "An attacker may register this hostname and intercept email."
                        ),
                        mx_priority=priority,
                        raw_dns_response=mx,
                    ))
            except Exception:
                continue
        return results

    # ── Scenario C: Zombie TXT ────────────────────────────────────────────────

    async def _check_zombie_txt(self, domain: str, dns_info: DNSInfo) -> list[StaleDnsResult]:
        results: list[StaleDnsResult] = []
        for txt in (dns_info.txt_records or []):
            txt_lower = txt.lower()
            for entry in TXT_VENDOR_PATTERNS:
                pattern = entry["pattern"].lower()
                if re.search(pattern, txt_lower):
                    results.append(StaleDnsResult(
                        domain=domain,
                        scenario="ZOMBIE_TXT",
                        record_type="TXT",
                        record_value=txt[:120],
                        reason=(
                            f"Potential stale TXT verification record for {entry['vendor']} — "
                            "cannot confirm without API access; review if account is still active"
                        ),
                        severity=entry["severity"],
                        recommendation=(
                            f"Confirm the {entry['vendor']} account is still active and owned by "
                            "your organization. Remove the TXT record if the account no longer exists."
                        ),
                        vendor_name=entry["vendor"],
                        txt_matched_pattern=entry["pattern"],
                        raw_dns_response=txt,
                    ))
                    break
        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _in_cloud_range(ip_str: str) -> str | None:
        try:
            addr = ip_address(ip_str)
            for provider, ranges in CLOUD_IP_RANGES.items():
                if any(addr in ip_network(cidr, strict=False) for cidr in ranges):
                    return provider
        except (AddressValueError, ValueError):
            pass
        return None

    @staticmethod
    def _in_cdn_range(ip_str: str) -> bool:
        from subreaper.data.waf_providers import CDN_PROVIDERS
        try:
            addr = ip_address(ip_str)
            return any(
                addr in ip_network(cidr, strict=False)
                for cfg in CDN_PROVIDERS.values()
                for cidr in cfg.ip_ranges
            )
        except (AddressValueError, ValueError):
            return False

    @staticmethod
    def _resolves(hostname: str) -> bool:
        try:
            socket.getaddrinfo(hostname, None)
            return True
        except socket.gaierror:
            return False

    async def _resolve_ptr(self, ip_str: str) -> str | None:
        loop = asyncio.get_running_loop()
        def _ptr() -> str | None:
            try:
                rev = dns.reversename.from_address(ip_str)
                answers = dns.resolver.resolve(rev, "PTR", lifetime=3)
                return answers[0].to_text().rstrip(".")
            except Exception:
                return None
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(_executor, _ptr), timeout=5
            )
        except Exception:
            return None