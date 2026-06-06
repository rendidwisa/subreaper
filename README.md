# SubReaper — Subdomain Takeover & Vulnerability Scanner

A scanner for **subdomain takeover** and **DNS vulnerability** detection.
Built for bug bounty hunters and pentesters with a **precision-focused detection** design.

---

## Key Features

- **Subdomain Takeover Detection** – Dangling CNAME, NS takeover, and unclaimed provider accounts (20+ services)
- **High-Accuracy Validation** – HTTP body fingerprint matching with scenario-based scoring
- **IP Intelligence** – Origin IP resolution with ASN, organization, country, city, and coordinates via MaxMind GeoLite2 (offline) or DNS fallback (online)
- **WAF & SNI Bypass** – Handles Cloudflare-protected services and Vercel SNI mismatches automatically
- **Concurrent Scanning** – Blazing-fast async scanning with configurable concurrency
- **Professional Reporting** – Colored terminal output, verbose DNS details, and JSON export
- **Precision-Focused Detection** – Multi-resolver consensus, wildcard guard, and negative signal filtering to minimize false positives

---

## Installation

```bash
# Clone the repository
git clone https://github.com/rendidwisa/subreaper.git
cd subreaper

# Install with pip
pip install .

# if error environment 
python3 -m venv subreaper
source subreaper/bin/activate
pip install .
```

After installation, the `subreaper` command will be available system-wide.

---

## Basic Usage

### Scan a single subdomain

```bash
subreaper -d sub.example.com
```

### Scan from a file containing subdomains

```bash
subreaper -f subs.txt
```

### Save results to JSON

```bash
subreaper -f subs.txt -o results.json
```

### Verbose mode (show all domains, including clean ones)

```bash
subreaper -f subs.txt -v
```

### Adjust concurrency and timeout

```bash
subreaper -f subs.txt -c 30 -t 15
```

### Pipe from another tool (e.g., subfinder)

```bash
subfinder -d target.com -silent | subreaper -f /dev/stdin -i -g -o result.json
```

### IP Intelligence (ASN & GeoIP)

SubReaper automatically resolves the origin IP of each CNAME target and, if the
optional MaxMind GeoLite2 databases are present, enriches every report with:

* **ASN** (Autonomous System Number) and organisation name
* **Country**, **city**, and approximate **coordinates**

This extra data helps verify whether the resolved IP really belongs to the
claimed provider (e.g. `AS16509 Amazon` for Heroku) and makes bug bounty
reports far more credible.

Without the databases, SubReaper still provides ASN and country via a
privacy-friendly DNS fallback, but city-level detail requires the databases.

### Obtaining the GeoLite2 Databases

1. Create a free MaxMind account at <https://www.maxmind.com/en/geolite2/signup>
2. After login, go to <https://www.maxmind.com/en/accounts/current/license-key>
   and copy your license key.
3. Run the integrated setup wizard:

```bash 
subreaper -S 
```
---

## Full Options

| Option             | Short | Description                                                     |
| ------------------ | ----- | ----------------------------------------------------------------|
| `--domain`         | `-d`  | Single domain/subdomain to scan                                 |
| `--file`           | `-f`  | File with one domain per line (use `/dev/stdin` for pipes)      |
| `--output`         | `-o`  | Save results to a JSON file                                     |
| `--concurrency`    | `-c`  | Number of parallel workers (default: 20)                        |
| `--timeout`        | `-t`  | DNS & HTTP timeout in seconds (default: 10)                     |
| `--nameservers`    | `-n`  | Comma-separated custom DNS servers                              |
| `--verbose`        | `-v`  | Show every domain status (including CLEAN/NXDOMAIN)             |
| `--setup-geoip`    | `-S`  | Download MaxMind GeoLite2 databases for enhanced IP             |
| `--ghost`          | `-g`  | Detect ghost services = live CNAME targets with foreign content |
| `--origin`         | `-i`  | Detect WAF bypass via exposed original IPs                      |
| `--validate-origin`| `-Vo` | Validate potential origin IPs with direct HTTP probes           |

---

## Requirements

Python 3.9 or newer

Dependencies (auto-installed via `pip install .`):

* aiohttp
* dnspython
* colorama
* geoip

---

## Contributing

Pull requests are welcome. Please read `CONTRIBUTING.md` for guidelines on adding fingerprints, running tests, and reporting bugs.

---

## License

MIT — free to use for pentesting, security research, and bug bounty.
