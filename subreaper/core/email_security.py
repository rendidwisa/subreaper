import asyncio
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from subreaper.models import DNSInfo, VulnResult
from subreaper.data.email_checks import (
    DKIM_COMMON_SELECTORS,
    SPF_ALL_MECHANISMS,
    SPF_INCLUDE_LIMIT,
    DMARC_POLICIES,
    RE_SPF_VERSION,
    RE_SPF_ALL,
    RE_SPF_INCLUDE,
    RE_DMARC_VERSION,
    RE_DMARC_POLICY,
    RE_DMARC_PCT,
    RE_DKIM_VERSION,
)

_executor = ThreadPoolExecutor(max_workers=10)


def _resolve_txt(fqdn: str) -> List[str]:
    """Blocking TXT lookup. Returns list of record strings or []."""
    try:
        answers = dns.resolver.resolve(fqdn, "TXT", lifetime=5)
        results = []
        for rdata in answers:
            txt = b" ".join(rdata.strings).decode("utf-8", errors="ignore").strip()
            results.append(txt)
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


async def _resolve_txt_async(fqdn: str) -> List[str]:
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(_executor, _resolve_txt, fqdn),
        timeout=8,
    )


class EmailSecurityChecker:

    def check_spf(self, domain: str, dns_info: DNSInfo) -> List[VulnResult]:
        results = []
        spf_record: Optional[str] = None

        for record in (dns_info.txt_records or []):
            if RE_SPF_VERSION.match(record):
                spf_record = record
                break

        if spf_record is None:
            results.append(VulnResult(
                domain=domain,
                vuln_type="EMAIL_MISCONFIG",
                severity="HIGH",
                service="SPF",
                description="No SPF record found",
                fix="Add a TXT record: v=spf1 include:<provider> -all",
                confidence="HIGH",
                details="No SPF record found",
            ))
            return results

        m = RE_SPF_ALL.search(spf_record)
        if m:
            mechanism = m.group(1).lower()
            entry = SPF_ALL_MECHANISMS.get(mechanism)
            if entry and entry[0] is not None:
                severity, desc = entry
                results.append(VulnResult(
                    domain=domain,
                    vuln_type="EMAIL_MISCONFIG",
                    severity=severity,
                    service="SPF",
                    description=f"SPF record uses `{mechanism}` — {desc}",
                    fix="Change SPF `all` mechanism to `-all`",
                    confidence="MEDIUM",
                    details=spf_record,
                ))

        include_count = len(RE_SPF_INCLUDE.findall(spf_record))
        if include_count > SPF_INCLUDE_LIMIT:
            results.append(VulnResult(
                domain=domain,
                vuln_type="EMAIL_MISCONFIG",
                severity="INFO",
                service="SPF",
                description=f"SPF record has {include_count} `include:` lookups (limit is 10)",
                fix="Consolidate SPF includes to stay under the 10 DNS lookup limit",
                confidence="LOW",
                details=spf_record,
            ))

        return results

    async def check_dmarc(self, domain: str) -> List[VulnResult]:
        results = []
        fqdn = f"_dmarc.{domain}"
        records = await _resolve_txt_async(fqdn)

        dmarc_record: Optional[str] = None
        for r in records:
            if RE_DMARC_VERSION.match(r):
                dmarc_record = r
                break

        if dmarc_record is None:
            results.append(VulnResult(
                domain=domain,
                vuln_type="EMAIL_MISCONFIG",
                severity="CRITICAL",
                service="DMARC",
                description="No DMARC record found",
                fix="Add TXT record at _dmarc.<domain>: v=DMARC1; p=reject; rua=mailto:dmarc@<domain>",
                confidence="HIGH",
                details="No DMARC record found",
            ))
            return results

        pm = RE_DMARC_POLICY.search(dmarc_record)
        if pm:
            policy = pm.group(1).lower()
            entry = DMARC_POLICIES.get(policy)
            if entry and entry[0] is not None:
                severity, desc = entry
                results.append(VulnResult(
                    domain=domain,
                    vuln_type="EMAIL_MISCONFIG",
                    severity=severity,
                    service="DMARC",
                    description=f"DMARC policy `p={policy}` — {desc}",
                    fix="Change DMARC policy to `p=reject`",
                    confidence="MEDIUM",
                    details=dmarc_record,
                ))

        pct_m = RE_DMARC_PCT.search(dmarc_record)
        if pct_m and int(pct_m.group(1)) < 100:
            results.append(VulnResult(
                domain=domain,
                vuln_type="EMAIL_MISCONFIG",
                severity="INFO",
                service="DMARC",
                description=f"DMARC `pct={pct_m.group(1)}` — policy not applied to all emails",
                fix="Set `pct=100` to enforce policy on all emails",
                confidence="LOW",
                details=dmarc_record,
            ))

        return results

    async def check_dkim(self, domain: str) -> List[VulnResult]:
        found_any = False
        tasks = [
            _resolve_txt_async(f"{sel}._domainkey.{domain}")
            for sel in DKIM_COMMON_SELECTORS
        ]
        all_results = await asyncio.gather(*tasks, return_exceptions=True)

        for records in all_results:
            if isinstance(records, list):
                for r in records:
                    if RE_DKIM_VERSION.search(r):
                        found_any = True
                        break
            if found_any:
                break

        if not found_any:
            return [VulnResult(
                domain=domain,
                vuln_type="EMAIL_MISCONFIG",
                severity="INFO",
                service="DKIM",
                description="No DKIM record found for common selectors",
                fix="Configure DKIM signing via your email provider and publish the public key",
                confidence="LOW",
                details="No DKIM record found for common selectors",
            )]

        return []