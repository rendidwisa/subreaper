"""
Reporter module.

All terminal output (colors, banners, per-domain status, vulnerability
details, scan summary) and file export (JSON) live here.

Keeping display logic separate from scan logic means:
  - Easy to add new output formats (Slack, CSV, HTML) without touching core.
  - Core modules stay importable without colorama side-effects.
"""

import json

from colorama import Back, Fore, Style

from subreaper.models import ScanResult, VulnResult


# ─────────────────────────────────────────────────────────────────────────────
# ASCII BANNER
# ─────────────────────────────────────────────────────────────────────────────

BANNER = f"""
{Fore.RED}{Style.BRIGHT}
  ███████╗██╗   ██╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
  ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ███████╗██║   ██║██████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ╚════██║██║   ██║██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ███████║╚██████╔╝██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}  [ Subdomain Takeover & DNS Vulnerability Scanner — v1.1 ]{Style.RESET_ALL}
{Fore.CYAN}  [ Pentest & Bug Bounty — By @rendidwisa ]{Style.RESET_ALL}
  {Fore.WHITE}{'━' * 72}{Style.RESET_ALL}
"""

_SEP = "━" * 60


class Reporter:
    """
    Handles all terminal output and file export for SubReaper.

    Can be subclassed or replaced to support alternative output backends
    (e.g. JSON-lines to stdout, Slack webhooks, HTML reports).
    """

    # ── status line ──────────────────────────────────────────────────────────

    @staticmethod
    def print_status(domain: str, status: str, extras: str = "") -> None:
        """Print a single-line status entry for *domain*."""
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")

        icons = {
            "VULN":  f"{Back.RED}{Fore.WHITE} !! VULN {Style.RESET_ALL}",
            "SCAN":  f"{Fore.CYAN}[SCAN]{Style.RESET_ALL}",
            "CLEAN": f"{Fore.GREEN}[CLEAN]{Style.RESET_ALL}",
            "ERROR": f"{Fore.YELLOW}[ERROR]{Style.RESET_ALL}",
            "DNS":   f"{Fore.BLUE}[DNS] {Style.RESET_ALL}",
        }
        icon = icons.get(status, f"[{status}]")
        print(
            f"  {Fore.WHITE}{ts}{Style.RESET_ALL} {icon} "
            f"{Fore.WHITE}{domain}{Style.RESET_ALL} {extras}"
        )

    # ── vulnerability detail block ───────────────────────────────────────────

    @staticmethod
    def print_vuln(result: ScanResult) -> None:
        """Print a detailed block for every vulnerability in *result*."""
        for vuln in result.vulnerabilities:
            conf_color = Fore.RED if vuln.confidence == "HIGH" else Fore.YELLOW
            print(f"\n  {_SEP}")
            print(f"  {Back.RED}{Fore.WHITE} VULNERABILITY FOUND {Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Domain    : {Fore.CYAN}{vuln.domain}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Type      : {Fore.RED}{vuln.vuln_type}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Service   : {Fore.MAGENTA}{vuln.service}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Confidence: {conf_color}{vuln.confidence}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Details   : {vuln.details}{Style.RESET_ALL}")

            if vuln.cname_chain:
                print(f"  {Fore.WHITE}CNAME Chain:{Style.RESET_ALL}")
                for hop in vuln.cname_chain:
                    print(f"    {Fore.YELLOW}→ {hop}{Style.RESET_ALL}")

            if vuln.evidence:
                print(f"  {Fore.WHITE}Evidence:{Style.RESET_ALL}")
                for ev in vuln.evidence:
                    print(f"    {Fore.RED}• {ev}{Style.RESET_ALL}")

            if vuln.http_status:
                print(
                    f"  {Fore.WHITE}HTTP Status: {Fore.RED}{vuln.http_status}{Style.RESET_ALL}"
                )

            print(f"  {Fore.WHITE}Fix       : {Fore.GREEN}{vuln.recommendation}{Style.RESET_ALL}")
            print(f"  {_SEP}\n")

    # ── scan summary ─────────────────────────────────────────────────────────

    @staticmethod
    def print_summary(results: list[ScanResult]) -> None:
        """Print aggregate statistics after a full scan run."""
        total = len(results)
        vulns  = [r for r in results if r.status == "VULNERABLE"]
        clean  = [r for r in results if r.status == "CLEAN"]
        nxd    = [r for r in results if r.status == "NXDOMAIN"]

        print(f"\n  {_SEP}")
        print(f"  {Style.BRIGHT}{Fore.WHITE}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"  {_SEP}")
        print(f"  Total domains  : {Fore.CYAN}{total}{Style.RESET_ALL}")
        print(f"  Vulnerable     : {Fore.RED}{len(vulns)}{Style.RESET_ALL}")
        print(f"  Clean          : {Fore.GREEN}{len(clean)}{Style.RESET_ALL}")
        print(f"  NXDOMAIN       : {Fore.YELLOW}{len(nxd)}{Style.RESET_ALL}")

        if vulns:
            print(f"\n  {Fore.RED}{Style.BRIGHT}DOMAIN VULNERABLE:{Style.RESET_ALL}")
            for r in vulns:
                for v in r.vulnerabilities:
                    conf_color = Fore.RED if v.confidence == "HIGH" else Fore.YELLOW
                    print(
                        f"    {Fore.RED}◆{Style.RESET_ALL} "
                        f"{Fore.WHITE}{r.domain}{Style.RESET_ALL} "
                        f"→ {Fore.MAGENTA}{v.service}{Style.RESET_ALL} "
                        f"[{conf_color}{v.confidence}{Style.RESET_ALL}] "
                        f"{Fore.YELLOW}({v.vuln_type}){Style.RESET_ALL}"
                    )

        print(f"  {_SEP}\n")

    # ── JSON export ──────────────────────────────────────────────────────────

    @staticmethod
    def export_json(results: list[ScanResult], output_path: str) -> None:
        """Serialize *results* to a JSON file at *output_path*."""
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
                        "details":        v.details,
                        "cname_chain":    v.cname_chain,
                        "evidence":       v.evidence,
                        "http_status":    v.http_status,
                        "recommendation": v.recommendation,
                    }
                    for v in r.vulnerabilities
                ],
            })

        with open(output_path, "w") as fh:
            json.dump(data, fh, indent=2)

        print(
            f"  {Fore.GREEN}✓ Results saved to: {output_path}{Style.RESET_ALL}"
        )