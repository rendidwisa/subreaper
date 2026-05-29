"""
Scanner engine.

SubReaper orchestrates DNS analysis, HTTP probing, and vulnerability
detection across a list of domains with configurable concurrency.
"""

import asyncio
import time
from datetime import datetime

from colorama import Fore, Style

from subreaper.core.dns_analyzer import DNSAnalyzer
from subreaper.core.http_prober import HTTPProber
from subreaper.core.vuln_detector import VulnDetector
from subreaper.models import ScanResult
from subreaper.reporter import Reporter


class SubReaper:
    """
    Main scanner engine.

    Parameters
    ----------
    concurrency : int
        Maximum number of domains scanned in parallel.
    timeout : int
        DNS and HTTP timeout in seconds.
    nameservers : list[str] | None
        Custom DNS resolvers. Defaults to 8.8.8.8 / 1.1.1.1 / 9.9.9.9.
    verbose : bool
        When True, print a status line for every domain, including clean ones.
    reporter : Reporter | None
        Custom reporter instance. Defaults to the built-in Reporter.
    """

    def __init__(
        self,
        concurrency: int = 20,
        timeout: int = 10,
        nameservers: list = None,
        verbose: bool = False,
        reporter: Reporter = None,
    ):
        self.concurrency = concurrency
        self.verbose     = verbose
        self.reporter    = reporter or Reporter()

        self.dns      = DNSAnalyzer(nameservers=nameservers, timeout=timeout)
        self.http     = HTTPProber(timeout=timeout)
        self.detector = VulnDetector(self.dns, self.http)

        self._semaphore: asyncio.Semaphore | None = None
        self.results: list[ScanResult] = []

    # ── single-domain scan ───────────────────────────────────────────────────

    async def scan_domain(self, domain: str) -> ScanResult | None:
        """
        Scan a single *domain*.

        Returns a ScanResult, or None if *domain* is blank.
        Thread-safe up to *concurrency* simultaneous calls.
        """
        domain = domain.strip().lower()
        if not domain:
            return None

        # Lazily create semaphore on first call (must be inside a running loop)
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.concurrency)

        async with self._semaphore:
            start  = time.time()
            result = ScanResult(domain=domain, timestamp=datetime.now().isoformat())

            if self.verbose:
                self.reporter.print_status(domain, "SCAN")

            # DNS analysis runs in a thread-pool executor to avoid blocking the
            # event loop with synchronous dnspython calls.
            dns_info = await asyncio.get_event_loop().run_in_executor(
                None, self.dns.analyze, domain
            )
            result.dns = dns_info

            if self.verbose and dns_info.cname_chain:
                chain_str = " → ".join(
                    [dns_info.cname_chain[0]["from"]]
                    + [h["to"] for h in dns_info.cname_chain]
                )
                self.reporter.print_status(domain, "DNS", f"CNAME: {chain_str}")

            # Vulnerability checks
            vulns = await self.detector.check_takeover(domain, dns_info)
            result.vulnerabilities = vulns

            # Timing
            elapsed            = (time.time() - start) * 1000
            result.scan_time_ms = round(elapsed, 2)

            # Status + output
            if vulns:
                result.status = "VULNERABLE"
                self.reporter.print_status(
                    domain, "VULN",
                    f"{Fore.RED}({len(vulns)} vulnerability found!){Style.RESET_ALL}",
                )
                self.reporter.print_vuln(result)

            elif dns_info.nxdomain:
                result.status = "NXDOMAIN"
                if self.verbose:
                    self.reporter.print_status(
                        domain, "ERROR",
                        f"{Fore.YELLOW}NXDOMAIN — domain not exist{Style.RESET_ALL}",
                    )
            else:
                result.status = "CLEAN"
                if self.verbose:
                    self.reporter.print_status(
                        domain, "CLEAN",
                        f"{Fore.GREEN}Secure ({elapsed:.0f}ms){Style.RESET_ALL}",
                    )

            self.results.append(result)
            return result

    # ── bulk scan ────────────────────────────────────────────────────────────

    async def scan_all(self, domains: list[str]) -> list[ScanResult]:
        """
        Scan all *domains* concurrently.

        Silently drops blank lines and swallows per-domain exceptions so one
        bad domain never aborts the entire batch.
        """
        tasks   = [self.scan_domain(d) for d in domains if d.strip()]
        raw     = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in raw if r and not isinstance(r, Exception)]

    # ── convenience wrappers ─────────────────────────────────────────────────

    def print_summary(self) -> None:
        """Print scan summary using the configured reporter."""
        self.reporter.print_summary(self.results)

    def export_json(self, output_path: str) -> None:
        """Export results to *output_path* as JSON."""
        self.reporter.export_json(self.results, output_path)