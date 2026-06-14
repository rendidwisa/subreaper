"""
Command-line interface for SubReaper.

Entry point when running:
    python -m subreaper
    subreaper        (after pip install)
"""

import argparse
import asyncio
import sys
import time
from datetime import datetime

from colorama import init
from rich.console import Console
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich import box

from subreaper.reporter import BANNER
from subreaper.scanner import SubReaper

init(autoreset=True)
console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSER
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subreaper",
        description="SubReaper v1.1.2 — Subdomain Takeover & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  subreaper -d sub.example.com
  subreaper -f subdomains.txt -o results.json -v
  subreaper -f subs.txt -c 50 -t 15
  subfinder -d target.com -silent | subreaper -f /dev/stdin
  subreaper -d vulnerable.com -i -g
        """,
    )

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "-d", "--domain",
        metavar="DOMAIN",
        help="Scan a single domain / subdomain",
    )
    input_group.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="Path to a file with one domain per line (use /dev/stdin for pipe input)",
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save results to a JSON file",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int, default=20, metavar="N",
        help="Parallel scan workers (default: 20)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int, default=10, metavar="SEC",
        help="DNS + HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-n", "--nameservers",
        metavar="NS1,NS2",
        help="Comma-separated custom nameservers (e.g. 8.8.8.8,1.1.1.1)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show status for every domain, including clean / NXDOMAIN",
    )
    parser.add_argument(
        "-i", "--origin",
        action="store_true",
        help="Detect WAF bypass via exposed original IPs",
    )
    parser.add_argument(
        "-g", "--ghost",
        action="store_true",
        help="Detect ghost services = live CNAME targets with foreign content",
    )
    parser.add_argument(
        "-Vo", "--validate-origins",
        action="store_true",
        help="Validate potential origin IPs with direct HTTP probes (improves accuracy but adds overhead)",
    )
    parser.add_argument(
        "-U", "--update-waf-db",
        action="store_true",
        help="Download latest WAF/CDN IP ranges from official sources (CloudFront, Cloudflare, Fastly)",
    )
    parser.add_argument(
        "-E", "--email-security",
        action="store_true",
        default=False,
        help="Check SPF, DMARC, and DKIM misconfiguration",
    )
    parser.add_argument(
        "-St", "--stale-dns",
        action="store_true",
        default=False,
        help="Detect stale DNS records (zombie A, MX, and TXT verification records)",
    )
    parser.add_argument(
        "-Co", "--cors-chain",
        action="store_true",
        default=False,
        help="Detect CORS misconfiguration chained with dangling/vulnerable subdomains (requires -f)",
    )
    parser.add_argument(
        "-Ds", "--dnssec",
        action="store_true",
        default=False,
        help="Check DNSSEC misconfiguration, NSEC zone walking, and zone transfer (AXFR)",
    )
    parser.add_argument(
        "-Sk", "--sinkhole",
        action="store_true",
        default=False,
        help="Detect DNS sinkhole and attempt service hijack with default credentials",
    )
    parser.add_argument(
        "-A", "--aggressive",
        action="store_true",
        help="Probe open ports and attempt default credential login on detected sinkholes",
    )
    parser.add_argument(
        "-S", "--setup-geoip",
        action="store_true",
        help="Download MaxMind GeoLite2 databases for enhanced IP intelligence",
    )
    return parser


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _load_domains(args: argparse.Namespace) -> list[str]:
    """Build and deduplicate the domain list from CLI args."""
    domains: list[str] = []

    if args.domain:
        domains.append(args.domain.strip())

    if args.file:
        try:
            with open(args.file) as fh:
                domains.extend(line.strip() for line in fh if line.strip())
        except FileNotFoundError:
            console.print(f"  [bold red]Error:[/bold red] file not found — {args.file}")
            sys.exit(1)

    # Preserve insertion order while removing duplicates
    return list(dict.fromkeys(domains))


def _print_header(domains: list[str], args: argparse.Namespace) -> None:
    """Print the pre-scan configuration summary."""
    ns_display = args.nameservers or "8.8.8.8, 1.1.1.1, 9.9.9.9 (default)"

    tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 1), min_width=62)
    tbl.add_column(style="cyan",  no_wrap=True, min_width=14)
    tbl.add_column(style="white")

    tbl.add_row("Target",      f"{len(domains)} domain{'s' if len(domains) > 1 else ''}")
    tbl.add_row("Concurrency", str(args.concurrency))
    tbl.add_row("Timeout",     f"{args.timeout}s")
    tbl.add_row("Nameservers", ns_display)
    tbl.add_row("Started at",  datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    if args.origin:
        tbl.add_row("Origin Check",  "[green]enabled[/green]")
    if args.ghost:
        tbl.add_row("Ghost Service", "[green]enabled[/green]")
    if args.dnssec:
        tbl.add_row("DNSSEC Check", "[green]enabled[/green]")
    if args.email_security:
        tbl.add_row("Email Security", "[green]enabled[/green]")
    if args.stale_dns:
        tbl.add_row("Stale DNS",     "[green]enabled[/green]")
    if args.cors_chain:
        tbl.add_row("CORS Chain",    "[green]enabled[/green]")
    if args.sinkhole:
        tbl.add_row("Sinkhole",      "[green]enabled[/green]")
    if args.aggressive:
        tbl.add_row("Aggressive",    "[green]enabled[/green]")
    if args.validate_origins:
        tbl.add_row("Validate Origins", "[green]enabled[/green]")
        
    console.print(tbl)
    console.print(Rule(style="dim"))
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC MAIN
# ─────────────────────────────────────────────────────────────────────────────

async def async_main() -> None:
    console.print(BANNER)

    parser = build_parser()
    args   = parser.parse_args()

    if args.setup_geoip:
        console.print("[bold cyan]SubReaper GeoIP Database Setup[/bold cyan]\n")
        console.print(
            "This wizard downloads the free MaxMind GeoLite2 databases.\n"
            "You need a license key from https://www.maxmind.com/en/geolite2/signup\n"
            "After logging in, get your key at https://www.maxmind.com/en/accounts/current/license-key\n"
        )
        license_key = console.input("[bold]Enter your license key (leave empty to cancel): [/bold]")
        if not license_key.strip():
            console.print("\n[yellow]No license key provided. Operation cancelled.[/yellow]")
            sys.exit(0)
            from subreaper.data.waf_updater import update_cache
            await update_cache()
            sys.exit(0)
        from subreaper.core.ip_intel import download_geoip_databases
        success = download_geoip_databases(license_key.strip())
        if success:
            console.print("\n[green]Setup complete. SubReaper will now use GeoIP databases.[/green]")
        else:
            console.print("\n[red]Download failed. SubReaper will continue using DNS fallback.[/red]")
        sys.exit(0)
        
    if args.update_waf_db:
        console.print("[bold cyan]SubReaper WAF Database Update[/bold cyan]\n")
        console.print("Downloading latest IP ranges from CloudFront, Cloudflare, Fastly...\n")
        from subreaper.data.waf_updater import update_cache
        await update_cache()
        sys.exit(0)

    if not args.setup_geoip and not args.domain and not args.file and not args.update_waf_db:
        parser.print_help()
        console.print(
            "\n  [bold red]Error:[/bold red] must specify either -d <domain> or -f <file>"
        )
        sys.exit(1)

    domains = _load_domains(args)
    if not domains:
        console.print("  [yellow]No domains to scan.[/yellow]")
        sys.exit(0)

    nameservers = None
    if args.nameservers:
        nameservers = [ns.strip() for ns in args.nameservers.split(",")]

    _print_header(domains, args)

    scanner = SubReaper(
        concurrency=args.concurrency,
        timeout=args.timeout,
        nameservers=nameservers,
        verbose=args.verbose,
        check_origin=args.origin,
        check_ghost_services=args.ghost,
        validate_origins=args.validate_origins,
        check_email_security=args.email_security,
        check_stale_dns=args.stale_dns,
        check_cors_chain=args.cors_chain,
        check_dnssec=args.dnssec,
        check_sinkhole=args.sinkhole,
    )

    start_total = time.time()
    await scanner.scan_all(domains)
    elapsed_total = time.time() - start_total

    scanner.print_summary(elapsed_total)

    if args.output:
        scanner.export_json(args.output)
        console.print(f"  [dim cyan]Saved →[/dim cyan] {args.output}\n")


# ─────────────────────────────────────────────────────────────────────────────
# SYNC WRAPPER (used by pyproject entry_point + direct invocation)
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Synchronous entry point registered in pyproject.toml."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        console.print("\n\n  [yellow]Scan interrupted.[/yellow]\n")
        sys.exit(0)