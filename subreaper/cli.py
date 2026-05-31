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
        description="SubReaper v1.1 — Subdomain Takeover & Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  subreaper -d sub.example.com
  subreaper -f subdomains.txt -o results.json -v
  subreaper -f subs.txt -c 50 -t 15
  subfinder -d target.com -silent | subreaper -f /dev/stdin
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

    if not args.domain and not args.file:
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