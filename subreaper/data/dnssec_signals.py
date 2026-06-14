from __future__ import annotations

DNSSEC_ALGORITHMS: dict[int, dict] = {
    1:  {"name": "RSAMD5",          "status": "WEAK",     "cve": "CVE-2022-25312",  "min_keylen": None},
    3:  {"name": "DSA",             "status": "WEAK",     "cve": None,              "min_keylen": None},
    5:  {"name": "RSASHA1",         "status": "WEAK",     "cve": "CVE-2023-50387",  "min_keylen": 1024},
    6:  {"name": "DSA-NSEC3-SHA1",  "status": "WEAK",     "cve": None,              "min_keylen": None},
    7:  {"name": "RSASHA1-NSEC3",   "status": "WEAK",     "cve": "CVE-2023-50387",  "min_keylen": 1024},
    8:  {"name": "RSASHA256",       "status": "MODERATE", "cve": None,              "min_keylen": 2048},
    10: {"name": "RSASHA512",       "status": "MODERATE", "cve": None,              "min_keylen": 2048},
    12: {"name": "ECC-GOST",        "status": "WEAK",     "cve": None,              "min_keylen": None},
    13: {"name": "ECDSAP256SHA256", "status": "STRONG",   "cve": None,              "min_keylen": None},
    14: {"name": "ECDSAP384SHA384", "status": "STRONG",   "cve": None,              "min_keylen": None},
    15: {"name": "ED25519",         "status": "STRONG",   "cve": None,              "min_keylen": None},
    16: {"name": "ED448",           "status": "STRONG",   "cve": None,              "min_keylen": None},
}

WEAK_ALGORITHM_NUMBERS: frozenset[int] = frozenset(
    k for k, v in DNSSEC_ALGORITHMS.items() if v["status"] == "WEAK"
)

NSEC_WALK_PROBE_PREFIX: str = "zzz-subreaper-probe"

ZONE_TRANSFER_RECORD_TYPES: tuple[str, ...] = (
    "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA",
    "SRV", "PTR", "CAA", "NAPTR",
)

WHOIS_AVAILABLE_SIGNALS: tuple[str, ...] = (
    "no match for",
    "not found",
    "no entries found",
    "domain not found",
    "status: available",
    "object does not exist",
    "no data found",
    "nothing found",
    "domain name not known",
    "is free",
    "is available",
)

WHOIS_SERVERS: dict[str, str] = {
    ".com":     "whois.verisign-grs.com",
    ".net":     "whois.verisign-grs.com",
    ".org":     "whois.pir.org",
    ".io":      "whois.nic.io",
    ".co":      "whois.nic.co",
    ".app":     "whois.nic.google",
    ".dev":     "whois.nic.google",
    ".ai":      "whois.nic.ai",
    ".xyz":     "whois.nic.xyz",
    ".me":      "whois.nic.me",
    ".id":      "whois.id",
    ".info":    "whois.afilias.net",
    ".biz":     "whois.biz",
    ".us":      "whois.nic.us",
    ".uk":      "whois.nic.uk",
    ".de":      "whois.denic.de",
    ".nl":      "whois.domain-registry.nl",
    ".eu":      "whois.eu",
}