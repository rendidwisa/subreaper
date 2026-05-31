"""
Reporter — terminal output and file export for SubReaper.

Display logic is fully separated from scan logic:
  - Core modules stay importable without rich side-effects.
  - Adding new output formats (CSV, Slack, HTML) only touches this file.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from subreaper.models import ScanResult, VulnResult


console = Console()

BANNER = """\
[red bold]
  ███████╗██╗   ██╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
  ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███████╗██║   ██║██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ╚════██║██║   ██║██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ███████║╚██████╔╝██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
[/red bold]
[yellow]  [ Subdomain Takeover & DNS Vulnerability Scanner — v1.1.0 ][/yellow]
[cyan]  [ Pentest & Bug Bounty — By @rendidwisa ][/cyan]
"""


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_score(details: str) -> Optional[int]:
    """Extract numeric score from 'Score: X/100' in details string."""
    m = re.search(r"Score:\s*(\d+)/100", details or "")
    return int(m.group(1)) if m else None


def _conf_style(confidence: str) -> str:
    return "red bold" if confidence == "HIGH" else "yellow bold"


def _status_text(status: str) -> Text:
    mapping = {
        "VULNERABLE": Text("!! VULN", style="bold red"),
        "CLEAN":      Text("CLEAN",   style="bold green"),
        "NXDOMAIN":   Text("NXDOMAIN",style="bold yellow"),
        "ERROR":      Text("ERROR",   style="bold yellow"),
    }
    return mapping.get(status, Text(status, style="dim"))


# ── Reporter ──────────────────────────────────────────────────────────────────

class Reporter:
    """
    All terminal output and file export for SubReaper.

    Subclass or replace to support alternative backends.
    """

    # ── banner + session header ───────────────────────────────────────────────

    @staticmethod
    def print_banner() -> None:
        console.print(BANNER)

    @staticmethod
    def print_session_info(
        total: int,
        concurrency: int,
        timeout: int,
        nameservers: list[str],
    ) -> None:
        t = Table(box=None, show_header=False, padding=(0, 1))
        t.add_column(style="cyan",  no_wrap=True, min_width=18)
        t.add_column(style="white", no_wrap=True)

        ns_str = ", ".join(nameservers) if nameservers else "8.8.8.8, 1.1.1.1, 9.9.9.9 (default)"
        started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        t.add_row("Target",       f"{total} domains")
        t.add_row("Concurrency",  str(concurrency))
        t.add_row("Timeout",      f"{timeout}s")
        t.add_row("Nameservers",  ns_str)
        t.add_row("Started at",   started)

        console.print(t)
        console.print()

    # ── progress bar (use as context manager around the scan loop) ────────────

    @staticmethod
    def make_progress() -> Progress:
        """
        Returns a rich Progress instance.

        Usage:
            with Reporter.make_progress() as prog:
                task = prog.add_task("", total=total_domains)
                for domain in domains:
                    result = await scan(domain)
                    prog.advance(task)
                    Reporter.print_result_line(result, prog)
        """
        return Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[bold cyan]SubReaper[/bold cyan]"),
            BarColumn(bar_width=36, complete_style="green", finished_style="green bold"),
            TaskProgressColumn(),
            TextColumn("[dim]·[/dim]"),
            TextColumn("{task.fields[vuln_count]} vuln", style="red"),
            console=console,
            transient=False,
        )

    # ── per-domain result line ────────────────────────────────────────────────

    @staticmethod
    def print_result_line(result: ScanResult) -> None:
        """Single result line — printed after each domain completes."""
        ts     = datetime.now().strftime("%H:%M:%S")
        status = _status_text(result.status)

        line = Text()
        line.append(f"  {ts} ", style="dim")
        line.append("[")
        line.append_text(status)
        line.append("] ")
        line.append(result.domain, style="white")

        if result.status == "VULNERABLE" and result.vulnerabilities:
            v = result.vulnerabilities[0]
            score = _parse_score(v.details)
            score_str = f" · score {score}/100" if score else ""
            line.append(
                f"  {v.service} · {v.confidence}{score_str}",
                style="red",
            )
        elif result.status == "NXDOMAIN":
            line.append("  domain not found", style="dim")

        console.print(line)

        # Immediately print vuln detail block below the line
        if result.status == "VULNERABLE":
            Reporter.print_vuln(result)

    # ── vulnerability detail block ────────────────────────────────────────────

    @staticmethod
    def print_vuln(result: ScanResult) -> None:
        for vuln in result.vulnerabilities:
            score     = _parse_score(vuln.details)
            score_str = f" · {score}/100" if score else ""
            c_style   = _conf_style(vuln.confidence)

            console.print()
            console.print(Rule(
                title="[on red][white] ⚠ VULNERABILITY FOUND [/white][/on red]",
                style="red dim",
            ))

            t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
            t.add_column(style="dim",   no_wrap=True, min_width=12)
            t.add_column(style="white", overflow="fold")

            t.add_row("Domain",     Text(vuln.domain,    style="cyan"))
            t.add_row("Type",       Text(vuln.vuln_type, style="red bold"))
            t.add_row("Service",    Text(vuln.service,   style="magenta"))
            t.add_row(
                "Confidence",
                Text(f"{vuln.confidence}{score_str}", style=c_style),
            )
            t.add_row("Details",    vuln.details or "—")

            if vuln.cname_chain:
                chain_text = Text()
                for hop in vuln.cname_chain:
                    chain_text.append(f"  → {hop}\n", style="yellow")
                t.add_row("CNAME Chain", chain_text)

            if vuln.evidence:
                ev_text = Text()
                for ev in vuln.evidence:
                    ev_text.append(f"  • {ev}\n", style="red dim")
                t.add_row("Evidence", ev_text)

            if vuln.http_status:
                t.add_row("HTTP Status", Text(str(vuln.http_status), style="red"))

            t.add_row("Fix", Text(vuln.recommendation, style="green"))

            console.print(t)
            console.print(Rule(style="red dim"))
            console.print()

    # ── scan summary ──────────────────────────────────────────────────────────

    @staticmethod
    def print_summary(results: list[ScanResult], elapsed: float) -> None:
        vulns = [r for r in results if r.status == "VULNERABLE"]
        clean = [r for r in results if r.status == "CLEAN"]
        nxd   = [r for r in results if r.status == "NXDOMAIN"]

        console.print(Rule("[bold white]SCAN SUMMARY[/bold white]", style="dim"))
        console.print()

        # Stats — plain rows, no card boxes
        stats = Table(box=None, show_header=False, padding=(0, 2))
        stats.add_column(style="dim",   no_wrap=True, min_width=20)
        stats.add_column(no_wrap=True)

        stats.add_row("Total domains",  Text(str(len(results)), style="cyan bold"))
        stats.add_row("Vulnerable",     Text(str(len(vulns)),   style="red bold"))
        stats.add_row("Clean",          Text(str(len(clean)),   style="green bold"))
        stats.add_row("NXDOMAIN",       Text(str(len(nxd)),     style="yellow bold"))

        console.print(stats)

        # Vulnerable domain list
        if vulns:
            console.print()
            console.print("  [red bold]DOMAIN VULNERABLE:[/red bold]")
            for r in vulns:
                for v in r.vulnerabilities:
                    score     = _parse_score(v.details)
                    score_str = f"  score {score}/100" if score else ""
                    c_style   = _conf_style(v.confidence)

                    line = Text("    ◆ ", style="red")
                    line.append(r.domain,       style="white")
                    line.append(" → ",          style="dim")
                    line.append(v.service,      style="magenta")
                    line.append("  ")
                    line.append(v.confidence,   style=c_style)
                    line.append(score_str,      style="dim")
                    line.append(f"  ({v.vuln_type})", style="yellow dim")
                    console.print(line)

        console.print()
        console.print(Rule(style="dim"))
        console.print(f"  [dim]Elapsed time: {elapsed:.2f}s[/dim]")
        console.print()

    # ── verbose per-domain DNS info ───────────────────────────────────────────

    @staticmethod
    def print_dns_detail(result: ScanResult) -> None:
        """Optional verbose DNS breakdown — call only when --verbose is set."""
        if not result.dns:
            return
        dns = result.dns
        parts: list[str] = []
        if dns.cname_chain:
            last = dns.cname_chain[-1]
            parts.append(f"CNAME → {last.get('to', '?')}")
        if dns.a_records:
            parts.append(f"{len(dns.a_records)} A record(s)")
        if dns.nxdomain:
            parts.append("NXDOMAIN")
        if parts:
            console.print(f"    [dim]└─ {' · '.join(parts)}[/dim]")

    # ── JSON export ───────────────────────────────────────────────────────────

    @staticmethod
    def export_json(results: list[ScanResult], path: str) -> None:
        data = []
        for r in results:
            data.append({
                "domain":       r.domain,
                "status":       r.status,
                "timestamp":    r.timestamp,
                "scan_time_ms": r.scan_time_ms,
                "dns": {
                    "a_records":      r.dns.a_records      if r.dns else [],
                    "cname_chain": [
                        {"from": h["from"], "to": h["to"]}
                        for h in (r.dns.cname_chain if r.dns else [])
                    ],
                    "nxdomain":       r.dns.nxdomain       if r.dns else False,
                    "dangling_cname": r.dns.dangling_cname if r.dns else False,
                },
                "vulnerabilities": [
                    {
                        "type":           v.vuln_type,
                        "service":        v.service,
                        "confidence":     v.confidence,
                        "score":          _parse_score(v.details),
                        "details":        v.details,
                        "cname_chain":    v.cname_chain,
                        "evidence":       v.evidence,
                        "http_status":    v.http_status,
                        "recommendation": v.recommendation,
                    }
                    for v in r.vulnerabilities
                ],
            })

        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)

        console.print(f"  [green]✓ Results saved → {path}[/green]")