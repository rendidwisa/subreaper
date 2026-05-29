# SubReaper — Subdomain Takeover & Vulnerability Scanner

A scanner for **subdomain takeover** and **DNS vulnerability** detection.
Built for bug bounty hunters and pentesters with a **zero false positive** design.

---

## Key Features

* Dangling CNAME detection (CNAME chains pointing to unregistered domains)
* Identifies 20+ services (GitHub Pages, Heroku, AWS S3, Azure, etc.)
* HTTP body fingerprint validation for high accuracy
* NS takeover detection
* Blazing-fast concurrent scanning
* Colored terminal output + JSON export

---

## Installation

```bash
# Clone the repository
git clone https://github.com/rendidwisa/subreaper.git
cd subreaper

# Install with pip
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
subfinder -d target.com -silent | subreaper -f /dev/stdin
```

---

## Full Options

| Option          | Short | Description                                                |
| --------------- | ----- | ---------------------------------------------------------- |
| `--domain`      | `-d`  | Single domain/subdomain to scan                            |
| `--file`        | `-f`  | File with one domain per line (use `/dev/stdin` for pipes) |
| `--output`      | `-o`  | Save results to a JSON file                                |
| `--concurrency` | `-c`  | Number of parallel workers (default: 20)                   |
| `--timeout`     | `-t`  | DNS & HTTP timeout in seconds (default: 10)                |
| `--nameservers` | `-n`  | Comma-separated custom DNS servers                         |
| `--verbose`     | `-v`  | Show every domain status (including CLEAN/NXDOMAIN)        |

---

## Requirements

Python 3.9 or newer

Dependencies (auto-installed via `pip install .`):

* aiohttp
* dnspython
* colorama

---

## Contributing

Pull requests are welcome. Please read `CONTRIBUTING.md` for guidelines on adding fingerprints, running tests, and reporting bugs.

---

## License

MIT — free to use for pentesting, security research, and bug bounty.
