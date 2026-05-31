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
    ):
        self.concurrency = concurrency
        self.verbose     = verbose
        self.reporter    = reporter or Reporter()

        self.dns      = DNSAnalyzer(nameservers=nameservers, timeout=timeout)
        self.http     = HTTPProber(timeout=timeout)
        self.detector = VulnDetector(self.dns, self.http)

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

            dns_info = await asyncio.get_event_loop().run_in_executor(
                None, self.dns.analyze, domain
            )
            result.dns = dns_info

            vulns = await self.detector.check_takeover(domain, dns_info)
            result.vulnerabilities = vulns

            elapsed             = (time.time() - start) * 1000
            result.scan_time_ms = round(elapsed, 2)

            if vulns:
                result.status = "VULNERABLE"
                svc    = vulns[0].service if vulns else ""
                detail = f"{len(vulns)} issue · {svc}" if svc else f"{len(vulns)} issue"
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
                if vulns:
                    self.reporter.print_vuln(result)
                elif self.verbose or result.status in ("NXDOMAIN", "VULNERABLE"):
                    if result.status == "CLEAN":
                        self.reporter.print_clean(result, verbose=self.verbose)
                    else:
                        self.reporter.print_status(domain, result.status)

            self.results.append(result)
            return result

    async def scan_all(self, domains: list[str]) -> list[ScanResult]:
        clean        = [d for d in domains if d.strip()]
        self._total  = len(clean)
        self._rows   = [{"domain": d.strip().lower(), "status": "SCANNING", "detail": "", "ms": ""} for d in clean]

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
            console.print(_build_table(self._rows, self._total))
        else:
            raw = await asyncio.gather(
                *[self.scan_domain(d) for d in clean],
                return_exceptions=True,
            )

        return [r for r in raw if r and not isinstance(r, Exception)]

    def print_summary(self, elapsed: float = 0.0) -> None:
        self.reporter.print_summary(self.results, elapsed)

    def export_json(self, output_path: str) -> None:
        self.reporter.export_json(self.results, output_path)