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

from colorama import Fore, Style, init

from subreaper.reporter import BANNER
from subreaper.scanner import SubReaper

init(autoreset=True)

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
  subreaper -f subdomains.txt -o hasil.json -v
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
            print(
                f"  {Fore.RED}Error: file tidak ditemukan — {args.file}{Style.RESET_ALL}"
            )
            sys.exit(1)

    # Preserve insertion order while removing duplicates
    return list(dict.fromkeys(domains))


def _print_header(domains: list[str], args: argparse.Namespace) -> None:
    """Print the pre-scan configuration summary."""
    ns_display = args.nameservers or "8.8.8.8, 1.1.1.1, 9.9.9.9 (default)"
    print(f"  {Fore.CYAN}Target     : {Fore.WHITE}{len(domains)} domain{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Concurrency: {Fore.WHITE}{args.concurrency}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Timeout    : {Fore.WHITE}{args.timeout}s{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Nameservers: {Fore.WHITE}{ns_display}{Style.RESET_ALL}")
    print(
        f"  {Fore.CYAN}Dimulai    : "
        f"{Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}"
    )
    print(f"  {'━' * 60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC MAIN
# ─────────────────────────────────────────────────────────────────────────────

async def async_main() -> None:
    print(BANNER)

    parser  = build_parser()
    args    = parser.parse_args()

    if not args.domain and not args.file:
        parser.print_help()
        print(
            f"\n  {Fore.RED}Error: harus ada -d <domain> atau -f <file>{Style.RESET_ALL}"
        )
        sys.exit(1)

    domains = _load_domains(args)
    if not domains:
        print(f"  {Fore.YELLOW}Tidak ada domain untuk di-scan.{Style.RESET_ALL}")
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

    scanner.print_summary()
    print(f"  {Fore.CYAN}Total waktu: {elapsed_total:.2f} detik{Style.RESET_ALL}\n")

    if args.output:
        scanner.export_json(args.output)


# ─────────────────────────────────────────────────────────────────────────────
# SYNC WRAPPER (used by pyproject entry_point + direct invocation)
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Synchronous entry point registered in pyproject.toml."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}Scan dihentikan.{Style.RESET_ALL}\n")
        sys.exit(0)