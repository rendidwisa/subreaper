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

from subreaper.models import ScanResult, VulnResult, GhostService


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
[yellow]  [ Subdomain Takeover & DNS Vulnerability Scanner — v1.1.2 ][/yellow]
[cyan]  [ Pentest & Bug Bounty — By @rendidwisa ][/cyan]
"""


# ── helpers ───────────────────────────────────────────────────────────────────

def _parse_score(details: str) -> Optional[int]:
    """Extract numeric score from 'Score: X/100' in details string."""
    m = re.search(r"Score:\s*(\d+)/100", details or "")
    return int(m.group(1)) if m else None


def _conf_style(confidence: str) -> str:
    return "red bold" if confidence == "HIGH" else "yellow bold"

def _vuln_type_style(vuln_type: str) -> str:
    return {
        "SUBDOMAIN_TAKEOVER":         "red bold",
        "DANGLING_CNAME":             "yellow bold",
        "NS_TAKEOVER":                "red bold",
        "UNCLAIMED_PROVIDER_ACCOUNT": "orange1 bold",
    }.get(vuln_type, "yellow dim")

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

    # ── HTTP provider signal headers to extract and pass to VulnDetector ────────────────
    @staticmethod
    def print_clean(result: ScanResult, verbose: bool = False) -> None:
        """Print a single CLEAN domain line, optionally with DNS detail."""
        ts   = datetime.now().strftime("%H:%M:%S")
        line = Text()
        line.append(f"  {ts} ", style="dim")
        line.append("[")
        line.append(Text("CLEAN", style="bold green"))
        line.append("] ")
        line.append(result.domain, style="white")

        if verbose and result.dns and result.dns.cname_chain:
            last = result.dns.cname_chain[-1].get("to", "")
            if last:
                line.append(f"  → {last}", style="dim")

        console.print(line)

    @staticmethod
    def print_status(domain: str, status: str) -> None:
        """Print a single status line for NXDOMAIN / ERROR states."""
        ts    = datetime.now().strftime("%H:%M:%S")
        label, style = {
            "NXDOMAIN": ("NXDOMAIN", "bold yellow"),
            "ERROR":    ("ERROR",    "bold yellow"),
        }.get(status, (status, "dim"))

        line = Text()
        line.append(f"  {ts} ", style="dim")
        line.append("[")
        line.append(Text(label, style=style))
        line.append("] ")
        line.append(domain, style="white")
        console.print(line)

    # ── vulnerability detail block ────────────────────────────────────────────
    @staticmethod
    def print_vuln(result: ScanResult) -> None:
        for vuln in result.vulnerabilities:
            score     = _parse_score(vuln.details)
            score_str = f" · {score}/100" if score else ""
            c_style   = _conf_style(vuln.confidence)

            console.print()
            if vuln.vuln_type == "UNCLAIMED_PROVIDER_ACCOUNT":
                console.print(Rule(
                    title="[on dark_orange][white] ⚠ UNCLAIMED ACCOUNT DETECTED [/white][/on dark_orange]",
                    style="orange1 dim",
                ))
            else:
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

            if vuln.origin_ips:
                ips_text = Text()
                for ip in vuln.origin_ips:
                    ips_text.append(f"{ip} ", style="cyan")
                t.add_row("Origin IPs", ips_text)

            if vuln.asn_info:
                asn_text = Text()
                for info in vuln.asn_info:
                    org = f" ({info['asn_org']})" if info.get('asn_org') else ""
                    city = f" - {info['city']}" if info.get('city') else ""
                    latlon = ""
                    if info.get('latitude') and info.get('longitude'):
                        latlon = f" ({info['latitude']:.2f},{info['longitude']:.2f})"
                    asn_text.append(
                        f"AS{info['asn']}{org} [{info['country']}{city}{latlon}]  ",
                        style="cyan"
                    )
                t.add_row("ASN / GeoIP", asn_text)

            t.add_row("Fix", Text(vuln.recommendation, style="green"))

            console.print(t)
            console.print(Rule(style="red dim"))
            console.print()


    @staticmethod
    def print_origin_result(domain: str, result: tuple) -> None:
        waf_detected, origin_ips, bypassable = result
        #if not waf_detected:
        #    return

        console.print()
        console.print(Rule(
            title="[on dark_orange][white] ⚠ WAF BYPASS SURFACE [/white][/on dark_orange]",
            style="orange1 dim",
        ))

        t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
        t.add_column(style="dim",   no_wrap=True, min_width=14)
        t.add_column(style="white", overflow="fold")

        t.add_row("Domain",       Text(domain, style="cyan"))
        waf_label = ", ".join(waf_detected) if waf_detected else "No WAF"
        t.add_row("WAF Detected", Text(waf_label, style="magenta"))

        if origin_ips:
            ip_text = Text()
            for path in origin_ips:
                ip_text.append(f"{path.ip}", style="cyan")
                ip_text.append(f"  via {path.via}  [{path.source}]\n", style="dim")
            t.add_row("Origin IPs", ip_text)

        t.add_row(
            "Bypassable",
            Text("YES — origin exposed", style="red bold") if bypassable
            else Text("NO",              style="green"),
        )

        console.print(t)
        console.print(Rule(style="orange1 dim"))
        console.print()

    @staticmethod
    def print_ghost_services(domain: str, services: list) -> None:
        if not services:
            return

        for gs in services:
            console.print()
            console.print(Rule(
                title="[on purple][white] ⚠ GHOST SERVICE DETECTED [/white][/on purple]",
                style="purple dim",
            ))

            t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
            t.add_column(style="dim",   no_wrap=True, min_width=14)
            t.add_column(style="white", overflow="fold")

            t.add_row("Domain",       Text(gs.domain,       style="cyan"))
            t.add_row("CNAME Target", Text(gs.cname_target, style="yellow"))
            t.add_row("Provider",     Text(gs.provider,     style="magenta"))
            t.add_row("HTTP Status",  Text(str(gs.http_status), style="red"))
            t.add_row("Severity",     Text(f"{gs.severity}/100",
                style="red bold" if gs.severity >= 80 else "yellow bold"))

            if gs.evidence:
                ev_text = Text()
                for ev in gs.evidence:
                    ev_text.append(f"  • {ev}\n", style="dim")
                t.add_row("Evidence", ev_text)

            t.add_row("Fix", Text(gs.recommendation, style="green"))

            console.print(t)
            console.print(Rule(style="purple dim"))
            console.print()

    # ── email security checks ────────────────────────────────────────────────
    @staticmethod
    def _print_email_security(results: list[ScanResult]) -> None:
        email_findings = []
        for r in results:
            for v in r.vulnerabilities:
                if v.vuln_type == "EMAIL_MISCONFIG":
                    email_findings.append((r.domain, v))
        if not email_findings:
            return
        console.print(Rule("EMAIL SECURITY", style="bold yellow"))
        grouped: dict = {}
        for domain, vuln in email_findings:
            grouped.setdefault(domain, []).append(vuln)

        for domain, vulns in grouped.items():
            summary_parts = []
            fixes = []
            for v in vulns:
                sev_color = {
                    "CRITICAL": "red", "HIGH": "yellow",
                    "MEDIUM": "cyan", "LOW": "green", "INFO": "dim",
                }.get(v.severity, "white")
                summary_parts.append(f"[{sev_color}]{v.description} ({v.severity})[/{sev_color}]")
                fixes.append(v.fix)
            console.print(f"  [bold]◆[/bold] {domain}")
            for part in summary_parts:
                console.print(f"     {part}")
            for fix in fixes:
                console.print(f"     [dim]Fix: {fix}[/dim]")

    # ── stale DNS ──────────────────────────────────────────────────────────

    @staticmethod
    def print_stale_dns(domain: str, results: list) -> None:
        if not results:
            return
        for r in results:
            console.print()
            console.print(Rule(
                title="[on yellow4][white] ⚠ STALE DNS RECORD [/white][/on yellow4]",
                style="yellow4 dim",
            ))
            t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
            t.add_column(style="dim",   no_wrap=True, min_width=14)
            t.add_column(style="white", overflow="fold")

            sev_style = "red bold" if r.severity == "HIGH" else "yellow bold" if r.severity == "MEDIUM" else "dim"
            t.add_row("Domain",    Text(r.domain,      style="cyan"))
            t.add_row("Scenario",  Text(r.scenario,    style="magenta"))
            t.add_row("Record",    Text(f"{r.record_type}: {r.record_value}", style="white"))
            t.add_row("Severity",  Text(r.severity,    style=sev_style))
            t.add_row("Reason",    r.reason)
            if r.vendor_name:
                t.add_row("Vendor",    Text(r.vendor_name, style="cyan"))
            if r.ip_owner_info:
                t.add_row("IP Owner",  Text(r.ip_owner_info, style="cyan"))
            if r.ip_reverse_dns:
                t.add_row("PTR",       Text(r.ip_reverse_dns, style="dim"))
            if r.mx_priority is not None:
                t.add_row("MX Priority", Text(str(r.mx_priority), style="dim"))
            t.add_row("Fix",       Text(r.recommendation, style="green"))

            console.print(t)
            console.print(Rule(style="yellow4 dim"))
            console.print()

    # ── scan summary ──────────────────────────────────────────────────────────

    @staticmethod
    def print_summary(results: list[ScanResult], elapsed: float, verbose: bool = False) -> None:
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
        # --- NEW: Ghost & WAF counters in stats table ---
        ghost_count = sum(len(getattr(r, "ghost_services", []) or []) for r in results)
        waf_count   = sum(
            1 for r in results
            if getattr(r, "origin_result", None) and r.origin_result[0] 
        )
        if ghost_count:
            stats.add_row("Ghost Services", Text(str(ghost_count), style="purple bold"))
        if waf_count:
            stats.add_row("WAF Exposed",    Text(str(waf_count),   style="orange1 bold"))
        stale_count = sum(
            len(getattr(r, "stale_dns_results", []) or []) for r in results
        )
        if stale_count:
            stats.add_row("Stale DNS", Text(str(stale_count), style="yellow bold"))
        cors_count = sum(
            len(getattr(r, "cors_chain_results", []) or []) for r in results
        )
        if cors_count:
            stats.add_row("CORS Chain", Text(str(cors_count), style="red bold"))

        dnssec_count = sum(
            1 for r in results
            if any(
                x.severity in ("HIGH", "MEDIUM") or x.nsec_walkable
                for x in getattr(r, "dnssec_results", [])
            )
        )
        if dnssec_count:
            stats.add_row("DNSSEC Issues", Text(str(dnssec_count), style="blue bold"))

        zone_count = sum(
            len([x for x in getattr(r, "zone_transfer_results", []) if x.success])
            for r in results
        )
        if zone_count:
            stats.add_row("Zone Transfer", Text(str(zone_count), style="red bold"))

        delegation_count = sum(
            len([x for x in getattr(r, "dangling_delegation_results", []) if x.is_vulnerable])
            for r in results
        )
        if delegation_count:
            stats.add_row("Dangling Delegation", Text(str(delegation_count), style="red bold"))
        sinkhole_count = sum(
            1 for r in results
            if getattr(r, "sinkhole_results", None) and r.sinkhole_results.sinkhole_detected
        )
        if sinkhole_count:
            stats.add_row("Sinkhole", Text(str(sinkhole_count), style="red bold"))

        hijack_count = sum(
            1 for r in results
            if getattr(r, "sinkhole_hijack_results", None) and r.sinkhole_hijack_results.hijackable
        )
        if hijack_count:
            stats.add_row("Sinkhole Hijackable", Text(str(hijack_count), style="red bold"))
        # -------------------------------------------------
        internal_count = sum(
            1 for r in results
            if getattr(r, "origin_result", None) and r.origin_result[1]
            and any(p.source == "INTERNAL_IP" for p in r.origin_result[1])
        )
        if internal_count:
            stats.add_row("Internal IPs",   Text(str(internal_count), style="red bold"))

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
                    line.append(f"  ({v.vuln_type})", style=_vuln_type_style(v.vuln_type))
                    console.print(line)
                    if v.origin_ips:
                        ip_line = Text("       IPs: ", style="dim")
                        ip_line.append(", ".join(v.origin_ips), style="cyan")
                        console.print(ip_line)
                    if v.asn_info:
                        asn_line = Text("       ASN: ", style="dim")
                        parts = []
                        for info in v.asn_info:
                            org = f" ({info['asn_org']})" if info.get('asn_org') else ""
                            city = f" - {info['city']}" if info.get('city') else ""
                            lat = info.get('latitude')
                            lon = info.get('longitude')
                            coord = f" ({lat:.2f},{lon:.2f})" if lat and lon else ""
                            parts.append(f"AS{info['asn']}{org} [{info['country']}{city}{coord}]")
                        asn_line.append(", ".join(parts), style="cyan")
                        console.print(asn_line)

        # ghost services list
        ghost_results = [
            (r, getattr(r, "ghost_services", []) or [])
            for r in results
            if getattr(r, "ghost_services", None)
        ]
        if ghost_results:
            console.print()
            console.print("  [purple bold]GHOST SERVICES DETECTED:[/purple bold]")
            for r, services in ghost_results:
                for gs in services:
                    sev_style = "red bold" if gs.severity >= 80 else "yellow bold"
                    line = Text("    ◆ ", style="purple")
                    line.append(getattr(gs, "domain", r.domain), style="white")
                    line.append(" → ", style="dim")
                    line.append(gs.provider, style="magenta")
                    line.append(f"  severity {gs.severity}/100  ", style=sev_style)
                    line.append(f"HTTP {gs.http_status}", style="dim")
                    console.print(line)
                    # CNAME target
                    cname_line = Text("       CNAME: ", style="dim")
                    cname_line.append(gs.cname_target, style="yellow")
                    console.print(cname_line)
                    # Fingerprint match
                    for ev in (gs.evidence or []):
                        if ev.startswith("PROVIDER_FP_MATCH:"):
                            fp_line = Text("       Match: ", style="dim")
                            fp_line.append(ev.replace("PROVIDER_FP_MATCH:", ""), style="red dim")
                            console.print(fp_line)
                            break

        # waf bypass surface list
        waf_results = [
            r for r in results
            if getattr(r, "origin_result", None) is not None
            and (r.origin_result[0] or r.origin_result[1])
        ]
        if waf_results:
            console.print()
            console.print("  [orange1 bold]WAF BYPASS SURFACE:[/orange1 bold]")
            for r in waf_results:
                waf_detected, origin_ips, bypassable = r.origin_result
                line = Text("    ◆ ", style="orange1")
                line.append(r.domain, style="white")
                line.append(" → ", style="dim")
                waf_label = ", ".join(waf_detected) if waf_detected else "No WAF"
                line.append(waf_label, style="magenta")
                line.append(
                    "  BYPASSABLE" if bypassable else "  protected",
                    style="red bold" if bypassable else "green",
                )
                console.print(line)
                if origin_ips:
                    unique_ips = list(dict.fromkeys(p.ip for p in origin_ips))
                    total_unique = len(unique_ips)
                    displayed = unique_ips[:6]
                    ip_list_str = ", ".join(displayed)

                    ip_line = Text("       IPs: ", style="dim")
                    ip_line.append(f"{total_unique} unique - ", style="cyan")
                    ip_line.append(ip_list_str, style="cyan")
                    if total_unique > 6:
                        ip_line.append(f"  ... +{total_unique - 6} more", style="dim cyan")
                    console.print(ip_line)
                    
        stale_results = [
            (r, getattr(r, "stale_dns_results", []) or [])
            for r in results
            if getattr(r, "stale_dns_results", None)
        ]
        if stale_results:
            console.print()
            console.print("  [yellow bold]STALE DNS RECORDS:[/yellow bold]")
            for r, findings in stale_results:
                for f in findings:
                    sev_style = "red bold" if f.severity == "HIGH" else "yellow bold"
                    line = Text("    ◆ ", style="yellow")
                    line.append(r.domain,    style="white")
                    line.append(" → ",       style="dim")
                    line.append(f.scenario,  style="magenta")
                    line.append(f"  {f.severity}", style=sev_style)
                    console.print(line)
                    rec_line = Text("       ", style="dim")
                    rec_line.append(f.record_type + ": ", style="dim")
                    rec_line.append(f.record_value[:60], style="cyan")
                    console.print(rec_line)

        cors_results = [
            r for r in results
            if getattr(r, "cors_chain_results", None)
        ]
        if cors_results:
            console.print()
            console.print("  [red bold]CORS CHAIN MISCONFIGURATION:[/red bold]")
            for r in cors_results:
                for f in r.cors_chain_results:
                    sev_style = "red bold" if f.severity == "CRITICAL" else "orange1 bold"
                    line = Text("    ◆ ", style="red")
                    line.append(f.affected_domain,  style="white")
                    line.append(" → ",              style="dim")
                    line.append(f.dangerous_origin, style="red")
                    line.append(f"  {f.severity}",  style=sev_style)
                    if f.credentials:
                        line.append("  [CREDENTIALS]", style="red bold")
                    console.print(line)
                    cors_line = Text("       CORS: ", style="dim")
                    cors_line.append(f.cors_value, style="yellow")
                    console.print(cors_line)

        internal_results = [
            r for r in results
            if getattr(r, "origin_result", None) and r.origin_result[1]
        ]
        internal_domains = []
        for r in internal_results:
            waf_detected, origin_ips, bypassable = r.origin_result
            private_ips = [p for p in origin_ips if p.source == "INTERNAL_IP"]
            if private_ips:
                internal_domains.append((r, private_ips))

        if internal_domains:
            console.print()
            console.print("  [red bold]INTERNAL IP EXPOSURE:[/red bold]")
            for r, ips in internal_domains:
                line = Text("    ◆ ", style="red")
                line.append(r.domain, style="white")
                line.append(" → ", style="dim")
                line.append(f"{len(ips)} private IP(s)", style="red")
                console.print(line)
                ip_line = Text("       IPs: ", style="dim")
                ip_line.append(", ".join(p.ip for p in ips), style="cyan")
                console.print(ip_line)
     
        sinkhole_r = [(r, r.sinkhole_results) for r in results if getattr(r, "sinkhole_results", None) and r.sinkhole_results.sinkhole_detected]
        if sinkhole_r:
            console.print()
            console.print("  [red bold]DNS SINKHOLE DETECTED:[/red bold]")
            for r, sr in sinkhole_r:
                line = Text("    ◆ ", style="red")
                line.append(r.domain, style="white")
                line.append(" → ", style="dim")
                line.append(sr.sinkhole_ip or "unknown", style="red bold")
                console.print(line)

        hijack_r = [(r, r.sinkhole_hijack_results) for r in results if getattr(r, "sinkhole_hijack_results", None) and r.sinkhole_hijack_results.hijackable]
        if hijack_r:
            console.print()
            console.print("  [red bold]SINKHOLE HIJACKABLE:[/red bold]")
            for r, hr in hijack_r:
                line = Text("    ◆ ", style="red bold")
                line.append(hr.sinkhole_ip, style="white")
                line.append(" → ", style="dim")
                line.append(f"{len(hr.hijacked_services)} service(s) hijacked", style="red")
                console.print(line)

        service_sinkhole_r = [
            (r, r.service_sinkhole_results) for r in results
            if getattr(r, "service_sinkhole_results", None) and r.service_sinkhole_results.detected
        ]
        if service_sinkhole_r:
            console.print()
            console.print("  [red bold]SERVICE SINKHOLE (Unclaimed Error Page):[/red bold]")
            for r, sr in service_sinkhole_r:
                line = Text("    ◆ ", style="red")
                line.append(r.domain, style="white")
                line.append(" → ", style="dim")
                line.append(sr.provider or "Unknown", style="magenta")
                if sr.claimable:
                    line.append(" [CLAIMABLE]", style="green bold")
                line.append(f"  {sr.confidence or '?'}", style="red bold")
                console.print(line)

        Reporter._print_email_security(results)

        # clean 
        if verbose:
            if clean:
                console.print()
                console.print("  [green bold]DOMAIN CLEAN:[/green bold]")
                for r in clean:
                    line = Text("    ◆ ", style="green")
                    line.append(r.domain, style="white")
                    if r.dns and r.dns.cname_chain:
                        last = r.dns.cname_chain[-1].get("to", "")
                        if last:
                            line.append(f"  → {last}", style="dim")
                    if r.dns and r.dns.a_records:
                        line.append(f"  [{', '.join(r.dns.a_records[:2])}]", style="dim cyan")
                    console.print(line)

            if nxd:
                console.print()
                console.print("  [yellow bold]DOMAIN NXDOMAIN:[/yellow bold]")
                for r in nxd:
                    line = Text("    ◆ ", style="yellow")
                    line.append(r.domain, style="dim")
                    console.print(line)

        console.print()
        console.print(Rule(style="dim"))
        console.print(f"  [dim]Elapsed time: {elapsed:.2f}s[/dim]")
        console.print()

    @staticmethod
    def print_cors_chain(findings: list) -> None:
        if not findings:
            return
        for f in findings:
            console.print()
            sev_style = "red bold" if f.severity == "CRITICAL" else "orange1 bold"
            console.print(Rule(
                title=f"[on red][white] CORS CHAIN MISCONFIGURATION [/white][/on red]",
                style="red dim",
            ))
            t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
            t.add_column(style="dim",   no_wrap=True, min_width=18)
            t.add_column(style="white", overflow="fold")

            t.add_row("Affected Domain",   Text(f.affected_domain,  style="cyan"))
            t.add_row("Dangerous Origin",  Text(f.dangerous_origin, style="red"))
            t.add_row("CORS Value",        Text(f.cors_value,       style="yellow"))
            t.add_row("Credentials",       Text("YES — session/cookie theft possible" if f.credentials else "NO", 
                                                style="red bold" if f.credentials else "green"))
            t.add_row("Severity",          Text(f.severity, style=sev_style))
            t.add_row("Type",              Text(f.vuln_type, style="magenta"))
            t.add_row("Fix",               Text(f.recommendation, style="green"))

            console.print(t)
            console.print(Rule(style="red dim"))
            console.print()

    @staticmethod
    def print_dnssec(domain: str, results: list) -> None:
        for r in results:
            if r.severity == "INFO" and not r.nsec_walkable:
                continue
            console.print()
            console.print(Rule(
                title="[on blue][white] ⚠ DNSSEC MISCONFIGURATION [/white][/on blue]",
                style="blue dim",
            ))
            t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
            t.add_column(style="dim",   no_wrap=True, min_width=18)
            t.add_column(style="white", overflow="fold")

            sev_style = "red bold" if r.severity == "HIGH" else "yellow bold"
            t.add_row("Domain",    Text(r.domain, style="cyan"))
            t.add_row("Has DNSSEC", Text("YES" if r.has_dnssec else "NO", style="green" if r.has_dnssec else "yellow"))
            if r.algorithm_name:
                t.add_row("Algorithm", Text(
                    f"{r.algorithm_name} (#{r.algorithm_number}) — {r.algorithm_status}",
                    style="red bold" if r.algorithm_status == "WEAK" else "white",
                ))
            if r.cve_reference:
                t.add_row("CVE", Text(r.cve_reference, style="red"))
            if r.nsec_walkable:
                t.add_row("NSEC Walking", Text(f"YES — {len(r.enumerated_names)} names enumerated", style="red bold"))
                if r.enumerated_names:
                    names_text = Text()
                    for name in r.enumerated_names[:20]:
                        names_text.append(f"  {name}\n", style="yellow")
                    if len(r.enumerated_names) > 20:
                        names_text.append(f"  ... +{len(r.enumerated_names) - 20} more\n", style="dim")
                    t.add_row("Enumerated", names_text)
            if r.rrsig_missing:
                t.add_row("RRSIG", Text("MISSING", style="red bold"))
            t.add_row("Severity", Text(r.severity, style=sev_style))
            t.add_row("Fix",      Text(r.recommendation, style="green"))

            console.print(t)
            console.print(Rule(style="blue dim"))
            console.print()

    @staticmethod
    def print_zone_transfer(domain: str, results: list) -> None:
        for r in results:
            if not r.success:
                continue
            console.print()
            console.print(Rule(
                title="[on red][white] ⚠ ZONE TRANSFER EXPOSED (AXFR) [/white][/on red]",
                style="red dim",
            ))
            t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
            t.add_column(style="dim",   no_wrap=True, min_width=18)
            t.add_column(style="white", overflow="fold")

            t.add_row("Domain",      Text(r.domain,      style="cyan"))
            t.add_row("Nameserver",  Text(r.nameserver,  style="yellow"))
            t.add_row("Records",     Text(str(r.record_count), style="red bold"))
            t.add_row("Severity",    Text(r.severity,    style="red bold"))

            if r.records:
                rec_text = Text()
                for rec in r.records[:30]:
                    rec_text.append(f"  {rec['name']:<30} {rec['type']:<8} {rec['value']}\n", style="dim")
                if len(r.records) > 30:
                    rec_text.append(f"  ... +{len(r.records) - 30} more records\n", style="dim cyan")
                t.add_row("Dump", rec_text)

            t.add_row("Fix", Text(r.recommendation, style="green"))

            console.print(t)
            console.print(Rule(style="red dim"))
            console.print()

    @staticmethod
    def print_dangling_delegation(domain: str, results: list) -> None:
        for r in results:
            if not r.is_vulnerable:
                continue
            console.print()
            console.print(Rule(
                title="[on red][white] ⚠ DANGLING CNAME DELEGATION [/white][/on red]",
                style="red dim",
            ))
            t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
            t.add_column(style="dim",   no_wrap=True, min_width=20)
            t.add_column(style="white", overflow="fold")

            t.add_row("Subdomain",        Text(r.subdomain,        style="cyan"))
            t.add_row("Delegated Domain", Text(r.delegated_domain, style="red bold"))
            t.add_row("Domain Status",    Text(r.delegated_domain_status.upper(),
                style="red bold" if r.is_vulnerable else "green"))
            t.add_row("Severity",         Text(r.severity, style="red bold"))
            if r.whois_raw:
                preview = r.whois_raw[:200].replace("\n", " ")
                t.add_row("WHOIS Preview", Text(preview, style="dim"))
            t.add_row("Fix", Text(r.recommendation, style="green"))

            console.print(t)
            console.print(Rule(style="red dim"))
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

    @staticmethod
    def print_sinkhole(domain: str, result) -> None:
        if not result or not result.sinkhole_detected:
            return
        console.print()
        console.print(Rule(
            title="[on red][white] ⚠ DNS SINKHOLE DETECTED [/white][/on red]",
            style="red dim",
        ))
        t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
        t.add_column(style="dim",   no_wrap=True, min_width=18)
        t.add_column(style="white", overflow="fold")
        t.add_row("Domain",          Text(domain, style="cyan"))
        t.add_row("Resolver",        Text(result.resolver_used, style="yellow"))
        t.add_row("Sinkhole IP",     Text(result.sinkhole_ip or "", style="red bold"))
        t.add_row("Severity",        Text(result.severity, style="red bold"))
        if result.internal_ips_exposed:
            ips_text = Text()
            for ip in result.internal_ips_exposed:
                ips_text.append(f"  {ip}\n", style="cyan")
            t.add_row("Internal IPs", ips_text)
        if result.evidence:
            ev_text = Text()
            for ev in result.evidence:
                ev_text.append(f"  • {ev}\n", style="dim")
            t.add_row("Evidence", ev_text)
        console.print(t)
        console.print(Rule(style="red dim"))
        console.print()

    @staticmethod
    def print_sinkhole_hijack(domain: str, result) -> None:
        if not result:
            return
        if not result.hijacked_services and not result.available_services:
            return
        console.print()
        sev_style = "red bold" if result.hijackable else "yellow bold"
        sev_label = "HIJACKABLE" if result.hijackable else "INTERNAL SERVICES EXPOSED"
        console.print(Rule(
            title=f"[on red][white] ⚠ SINKHOLE {sev_label} [/white][/on red]",
            style="red dim",
        ))
        t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
        t.add_column(style="dim",   no_wrap=True, min_width=18)
        t.add_column(style="white", overflow="fold")
        t.add_row("Sinkhole IP", Text(result.sinkhole_ip, style="red bold"))
        if result.hijacked_services:
            hijack_text = Text()
            for svc in result.hijacked_services:
                hijack_text.append(f"  Port {svc.port}: {svc.default_creds} @ {svc.login_endpoint}\n", style="green bold")
            t.add_row("Hijacked", hijack_text)
        else:
            t.add_row("Hijackable", Text("NO — no default credentials work", style="yellow"))
        if result.available_services:
            svc_text = Text()
            for svc in result.available_services:
                svc_text.append(f"  Port {svc.port}: {svc.service} ({svc.banner})\n", style="dim")
            t.add_row("Services", svc_text)
        t.add_row("Severity", Text(result.severity, style=sev_style))
        t.add_row("Fix", Text(result.recommendation, style="green"))
        console.print(t)
        console.print(Rule(style="red dim"))
        console.print()

    @staticmethod
    def print_service_sinkhole(domain: str, result) -> None:
        if not result or not result.detected:
            return
        console.print()
        console.print(Rule(
            title="[on red][white] ⚠ SERVICE SINKHOLE DETECTED [/white][/on red]",
            style="red dim",
        ))
        t = Table(box=None, show_header=False, padding=(0, 1), min_width=60)
        t.add_column(style="dim",   no_wrap=True, min_width=18)
        t.add_column(style="white", overflow="fold")
        t.add_row("Domain",     Text(domain, style="cyan"))
        t.add_row("Provider",   Text(result.provider or "?", style="magenta"))
        t.add_row("Confidence", Text(result.confidence or "?", style="red bold"))
        t.add_row("Claimable",  Text(
            "YES" if result.claimable else "NO",
            style="green bold" if result.claimable else "yellow"
        ))
        t.add_row("HTTP Status", Text(str(result.status or ""), style="cyan"))
        if result.evidence:
            for ev in result.evidence:
                ev_text.append(f"  • {ev}\n", style="dim")
            t.add_row("Evidence", ev_text)
        console.print(t)
        console.print(Rule(style="red dim"))
        console.print()

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
                        "origin_ips":     v.origin_ips,
                        "asn_info":       v.asn_info,
                        "recommendation": v.recommendation,
                    }
                    for v in r.vulnerabilities
                ],
                "origin_result": (
                    {
                        "waf_detected":  r.origin_result[0],
                        "origin_ips":    [
                            {"ip": p.ip, "via": p.via, "source": p.source, "label": p.label}
                            for p in r.origin_result[1]
                        ],
                        "bypassable":    r.origin_result[2],
                    }
                    if getattr(r, "origin_result", None) else None
                ),
                "ghost_services": [
                    {
                        "cname_target":   gs.cname_target,
                        "provider":       gs.provider,
                        "http_status":    gs.http_status,
                        "severity":       gs.severity,
                        "evidence":       gs.evidence,
                        "recommendation": gs.recommendation,
                    }
                    for gs in getattr(r, "ghost_services", [])
                ], 
                "sinkhole": {
                    "detected":        r.sinkhole_results.sinkhole_detected if r.sinkhole_results else False,
                    "sinkhole_ip":     r.sinkhole_results.sinkhole_ip if r.sinkhole_results else None,
                    "internal_ips":    r.sinkhole_results.internal_ips_exposed if r.sinkhole_results else [],
                    "evidence":        r.sinkhole_results.evidence if r.sinkhole_results else [],
                } if getattr(r, "sinkhole_results", None) else None,

                "sinkhole_hijack": {
                    "hijackable":       r.sinkhole_hijack_results.hijackable if r.sinkhole_hijack_results else False,
                    "hijacked_services": [
                        {"port": svc.port, "creds": svc.default_creds, "endpoint": svc.login_endpoint}
                        for svc in (r.sinkhole_hijack_results.hijacked_services if r.sinkhole_hijack_results else [])
                    ],
                    "available_services": [
                        {"port": svc.port, "service": svc.service, "banner": svc.banner}
                        for svc in (r.sinkhole_hijack_results.available_services if r.sinkhole_hijack_results else [])
                    ],
                    "evidence":         r.sinkhole_hijack_results.evidence if r.sinkhole_hijack_results else [],
                } if getattr(r, "sinkhole_hijack_results", None) else None,
                "service_sinkhole": {
                    "detected":    r.service_sinkhole_results.detected,
                    "provider":    r.service_sinkhole_results.provider,
                    "claimable":   r.service_sinkhole_results.claimable,
                    "confidence":  r.service_sinkhole_results.confidence,
                    "http_status": r.service_sinkhole_results.status,
                    "evidence":    r.service_sinkhole_results.evidence,
                } if getattr(r, "service_sinkhole_results", None) else None,
            })

        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)

        console.print(f"  [green]✓ Results saved → {path}[/green]")