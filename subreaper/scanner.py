"""
Scanner engine.

SubReaper orchestrates DNS analysis, HTTP probing, and vulnerability
detection across a list of domains with configurable concurrency.
"""

import asyncio
import time
from datetime import datetime

from subreaper.core.dns_analyzer import DNSAnalyzer
from subreaper.core.http_prober import HTTPProber
from subreaper.core.vuln_detector import VulnDetector
from subreaper.models import ScanResult
from subreaper.reporter import Reporter
from subreaper.core.email_security import EmailSecurityChecker
from subreaper.core.stale_dns_detector import StaleDnsDetector
from subreaper.core.cors_analyzer import CorsAnalyzer
from subreaper.core.dnssec_checker import DnssecChecker
from subreaper.core.sinkhole_hijack import SinkholeHijacker

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

_STATUS_STYLE = {
    "VULNERABLE": ("[VULN]",     "bold red"),
    "NXDOMAIN":   ("[NXDOMAIN]", "yellow"),
    "CLEAN":      ("[CLEAN]",    "green"),
    "SCANNING":   ("[...]",      "dim cyan"),
}


def _build_table(rows: list[dict], total: int) -> Table:
    done = sum(1 for r in rows if r["status"] != "SCANNING")
    vuln = sum(1 for r in rows if r["status"] == "VULNERABLE")

    title = Text()
    title.append("SubReaper", style="bold red")
    title.append(f"  {done}/{total}", style="dim white")
    title.append("  ·  ", style="dim")
    title.append(f"{vuln} vuln", style="bold red" if vuln else "dim white")

    tbl = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold white",
        expand=False,
        min_width=72,
    )
    tbl.add_column("Domain",  style="cyan", no_wrap=True, min_width=34)
    tbl.add_column("Status",  justify="center",            min_width=12)
    tbl.add_column("Detail",  style="dim white",           min_width=22)
    tbl.add_column("ms",      justify="right",             min_width=6)

    for r in rows:
        label, style = _STATUS_STYLE.get(r["status"], ("[?]", "white"))
        ms_cell = Text("…", style="dim") if r["status"] == "SCANNING" else str(r.get("ms", ""))
        tbl.add_row(
            r["domain"],
            Text(label, style=style),
            r.get("detail", ""),
            ms_cell,
        )

    return tbl


class SubReaper:
    def __init__(
        self,
        concurrency: int = 20,
        timeout: int = 10,
        nameservers: list = None,
        verbose: bool = False,
        reporter: Reporter = None,
        check_origin: bool = False,
        check_ghost_services: bool = False,
        validate_origins: bool = False,
        check_email_security: bool = False,
        check_stale_dns: bool = False,
        check_cors_chain: bool = False,
        check_dnssec: bool = False,
        check_sinkhole: bool = False,
        aggressive: bool = False
    ):
        self.concurrency = concurrency
        self.verbose     = verbose
        self.check_origin        = check_origin
        self.check_ghost_services = check_ghost_services
        self.check_stale_dns = check_stale_dns
        self.stale_dns = StaleDnsDetector()
        self.validate_origins     = validate_origins
        self.check_email_security = check_email_security
        self.check_cors_chain = check_cors_chain
        self.cors_analyzer    = CorsAnalyzer()
        self.check_dnssec = check_dnssec
        self.dnssec_checker = DnssecChecker()
        self.check_sinkhole = check_sinkhole
        self.aggressive = aggressive
        self.sinkhole_hijacker = SinkholeHijacker(timeout=timeout)
        self.reporter    = reporter or Reporter()

        self.dns      = DNSAnalyzer(nameservers=nameservers, timeout=timeout)
        self.http     = HTTPProber(timeout=timeout)
        self.detector = VulnDetector(self.dns, self.http)
        self.email_checker = EmailSecurityChecker()

        self._semaphore: asyncio.Semaphore | None = None
        self.results: list[ScanResult] = []

        self._live:  Live | None  = None
        self._rows:  list[dict]   = []
        self._total: int          = 0

    def _refresh(self) -> None:
        if self._live:
            self._live.update(_build_table(self._rows, self._total))

    def _row_index(self, domain: str) -> int:
        for i, r in enumerate(self._rows):
            if r["domain"] == domain:
                return i
        return -1

    async def scan_domain(self, domain: str) -> ScanResult | None:
        domain = domain.strip().lower()
        if not domain:
            return None

        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)

        async with self._semaphore:
            start  = time.time()
            result = ScanResult(domain=domain, timestamp=datetime.now().isoformat())

            idx = self._row_index(domain)
            if idx == -1:
                self._rows.append({"domain": domain, "status": "SCANNING", "detail": "", "ms": ""})
                idx = len(self._rows) - 1
            self._refresh()

            dns_info = await asyncio.get_running_loop().run_in_executor(
                None, self.dns.analyze, domain
            )
            result.dns = dns_info

            vulns = await self.detector.check_takeover(domain, dns_info)
            origin_result = None
            if self.check_origin:
                origin_result = await self.detector.check_origin_exposure(
                    domain, dns_info, validate=self.validate_origins
                )

            ghost_services = []
            if self.check_ghost_services:
                ghost_services = await self.detector.check_ghost_service(domain, dns_info)

            result.origin_result  = origin_result
            result.ghost_services = ghost_services
            result.vulnerabilities = vulns
            if self.check_email_security and domain in self._email_apex_domains:
                spf_vulns = await asyncio.get_running_loop().run_in_executor(
                    None, self.email_checker.check_spf, domain, dns_info)
                dmarc_task = self.email_checker.check_dmarc(domain)
                dkim_task  = self.email_checker.check_dkim(domain)
                dmarc_vulns, dkim_vulns = await asyncio.gather(dmarc_task, dkim_task)
                result.vulnerabilities.extend(spf_vulns)
                result.vulnerabilities.extend(dmarc_vulns)
                result.vulnerabilities.extend(dkim_vulns)

            elapsed             = (time.time() - start) * 1000
            
            result.scan_time_ms = round(elapsed, 2)
            
            stale_dns_results = []
            if self.check_stale_dns:
                stale_dns_results = await self.stale_dns.detect(domain, dns_info)

            result.stale_dns_results = stale_dns_results
            dnssec_results        = []
            zone_transfer_results = []
            dangling_delegation_results = []

            if self.check_dnssec and result.dns:
                cname_pairs = [
                    (hop["from"], hop["to"])
                    for hop in (result.dns.cname_chain or [])
                    if hop.get("from") and hop.get("to")
                ]

                dnssec_results, zone_transfer_results, dangling_delegation_results = (
                    await self.dnssec_checker.check_all(domain, cname_pairs)
                )

            result.dnssec_results            = dnssec_results
            result.zone_transfer_results     = zone_transfer_results
            result.dangling_delegation_results = dangling_delegation_results

            sinkhole_results = None
            sinkhole_hijack_results = None
            service_sinkhole_results = None
            if self.check_sinkhole and result.dns:
                sinkhole_data = await asyncio.get_running_loop().run_in_executor(
                    None, self.sinkhole_hijacker.analyze, domain, result.dns, self.aggressive
                )
                sinkhole_results = sinkhole_data.get("sinkhole")
                sinkhole_hijack_results = sinkhole_data.get("hijack")
                result.service_sinkhole_results = sinkhole_data.get("service_sinkhole")
            result.sinkhole_results = sinkhole_results
            result.sinkhole_hijack_results = sinkhole_hijack_results
            result.service_sinkhole_results = service_sinkhole_results 
            

            if result.vulnerabilities:
                result.status = "VULNERABLE"
                svc    = result.vulnerabilities[0].service if result.vulnerabilities else ""
                detail = f"{len(result.vulnerabilities)} issue · {svc}" if svc else f"{len(result.vulnerabilities)} issue"
                self._rows[idx] = {"domain": domain, "status": "VULNERABLE", "detail": detail, "ms": f"{elapsed:.0f}"}

            elif dns_info.nxdomain:
                result.status = "NXDOMAIN"
                self._rows[idx] = {"domain": domain, "status": "NXDOMAIN", "detail": "no record", "ms": f"{elapsed:.0f}"}

            else:
                result.status = "CLEAN"
                hint = ""
                if dns_info.cname_chain:
                    hint = f"→ {dns_info.cname_chain[-1]['to'][:26]}"
                self._rows[idx] = {"domain": domain, "status": "CLEAN", "detail": hint, "ms": f"{elapsed:.0f}"}

            self._refresh()

            if not self._live:
                if result.vulnerabilities:
                    self.reporter.print_vuln(result)
                elif self.verbose or result.status in ("NXDOMAIN", "VULNERABLE"):
                    if result.status == "CLEAN":
                        self.reporter.print_clean(result, verbose=self.verbose)
                    else:
                        self.reporter.print_status(domain, result.status)
                if origin_result and origin_result[0]:
                    self.reporter.print_origin_result(domain, origin_result)
                if ghost_services:
                    self.reporter.print_ghost_services(domain, ghost_services)
                if stale_dns_results:
                    self.reporter.print_stale_dns(domain, stale_dns_results)
                if result.dnssec_results:
                    self.reporter.print_dnssec(domain, result.dnssec_results)
                if result.zone_transfer_results:
                    self.reporter.print_zone_transfer(domain, result.zone_transfer_results)
                if result.dangling_delegation_results:
                    self.reporter.print_dangling_delegation(domain, result.dangling_delegation_results)
                    
            self.results.append(result)
            return result

    async def scan_all(self, domains: list[str]) -> list[ScanResult]:
        clean        = [d for d in domains if d.strip()]
        self._total  = len(clean)
        self._rows   = [{"domain": d.strip().lower(), "status": "SCANNING", "detail": "", "ms": ""} for d in clean]
        clean_set = set(clean)
        self._email_apex_domains = {
            d for d in clean 
            if not any(d != other and d.endswith("." + other) for other in clean_set)
        }
        if console.is_terminal:
            with Live(
                _build_table(self._rows, self._total),
                console=console,
                refresh_per_second=12,
                transient=True,
            ) as live:
                self._live = live
                raw = await asyncio.gather(
                    *[self.scan_domain(d) for d in clean],
                    return_exceptions=True,
                )
                self._live = None
            self.results = [r for r in raw if r and not isinstance(r, Exception)]

            if self.check_cors_chain and len(self.results) > 1:
                cors_findings = await self.cors_analyzer.analyze(self.results)
                domain_map = {r.domain: r for r in self.results}
                for finding in cors_findings:
                    r = domain_map.get(finding.affected_domain)
                    if r:
                        r.cors_chain_results.append(finding)
                if cors_findings:
                    self.reporter.print_cors_chain(cors_findings)

        else:
            raw = await asyncio.gather(
                *[self.scan_domain(d) for d in clean],
                return_exceptions=True,
            )
        # debug
        for domain, r in zip(clean, raw):
            if isinstance(r, Exception):
                console.print(f"[red]ERROR [{domain}]: {r}[/red]")
        self.results = [r for r in raw if r and not isinstance(r, Exception)]
        return self.results

    def print_summary(self, elapsed: float = 0.0) -> None:
        self.reporter.print_summary(self.results, elapsed, verbose=self.verbose)

    def export_json(self, output_path: str) -> None:
        self.reporter.export_json(self.results, output_path)