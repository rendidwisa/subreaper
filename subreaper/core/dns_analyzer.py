"""
DNS analysis module.

Handles DNS resolution, CNAME chain traversal, and provider classification.
Each CNAME hop is enriched with provider metadata and trust scoring.
"""

import re
import socket

import dns.exception
import dns.resolver

from subreaper.data.fingerprints import TAKEOVER_FINGERPRINTS
from subreaper.models import DNSInfo


_SUPPLEMENTARY_PROVIDERS = [
    {
        "cname_patterns": ["googleapis.com", "appspot.com", "googleusercontent.com"],
        "service": "Google Cloud",
        "provider_type": "Cloud",
        "provider_group": "GCP",
        "claimable": False,
        "risk_weight": 20,
    },
    {
        "cname_patterns": ["firebaseapp.com", "web.app"],
        "service": "Firebase",
        "provider_type": "Cloud",
        "provider_group": "GCP",
        "claimable": False,
        "risk_weight": 25,
    },
]

HOP_TRUST = {
    "SaaS": 85,
    "CDN": 80,
    "Cloud": 75,
    "Unknown": 40,
    "Dangling": 0,
}


class DNSAnalyzer:

    DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    MAX_CNAME_HOPS = 15

    def __init__(self, nameservers: list = None, timeout: int = 5):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.resolver.nameservers = nameservers or self.DEFAULT_NAMESERVERS
        self._provider_map = self._build_provider_map()

    @staticmethod
    def _build_provider_map() -> list[dict]:
        entries = []
        for fp in TAKEOVER_FINGERPRINTS + _SUPPLEMENTARY_PROVIDERS:
            entries.append({
                "patterns": fp["cname_patterns"],
                "service": fp["service"],
                "provider_type": fp.get("provider_type", "Unknown"),
                "provider_group": fp.get("provider_group", "Unknown"),
                "claimable": fp.get("claimable"),
                "risk_weight": fp.get("risk_weight", 50),
            })
        return entries

    @staticmethod
    def _matches_domain_boundary(target: str, pattern: str) -> bool:
        target = target.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        regex = r"(?:^|\.)" + re.escape(pattern) + r"(?:\.|$)"
        return bool(re.search(regex, target))

    def _classify_target(self, target: str) -> dict:
        normalized = target.lower().rstrip(".")
        for entry in self._provider_map:
            for pattern in entry["patterns"]:
                if self._matches_domain_boundary(normalized, pattern):
                    ptype = entry["provider_type"]
                    return {
                        "provider_hint": entry["service"],
                        "provider_type": ptype,
                        "provider_group": entry["provider_group"],
                        "is_cloud_provider": ptype in ("Cloud", "CDN"),
                        "claimable": entry["claimable"],
                        "hop_trust": HOP_TRUST.get(ptype, HOP_TRUST["Unknown"]),
                    }
        return {
            "provider_hint": None,
            "provider_type": "Unknown",
            "provider_group": None,
            "is_cloud_provider": False,
            "claimable": None,
            "hop_trust": HOP_TRUST["Unknown"],
        }

    def resolve(self, domain: str, rdtype: str) -> list:
        try:
            answers = self.resolver.resolve(domain, rdtype)
            return [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            return ["__NXDOMAIN__"]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.Timeout:
            return ["__TIMEOUT__"]
        except dns.exception.DNSException:
            return []

    def get_cname_chain(self, domain: str) -> list:
        chain = []
        current = domain
        visited: set = set()
        hop_count = 0
        remaining = self.MAX_CNAME_HOPS

        while remaining > 0:
            if current in visited:
                break
            visited.add(current)

            try:
                answers = self.resolver.resolve(current, "CNAME")
                target = str(list(answers)[0]).rstrip(".")
                hop = {"from": current, "to": target}
                hop.update(self._classify_target(target))
                chain.append(hop)
                current = target
                hop_count += 1
                remaining -= 1

            except dns.resolver.NXDOMAIN:
                if hop_count == 0:
                    return []
                chain.append({
                    "from": current,
                    "to": "NXDOMAIN",
                    "dangling": True,
                    "provider_hint": None,
                    "provider_type": "Unknown",
                    "provider_group": None,
                    "is_cloud_provider": False,
                    "claimable": None,
                    "hop_trust": HOP_TRUST["Dangling"],
                })
                break

            except dns.resolver.NoAnswer:
                break

            except dns.exception.DNSException:
                break

        return chain

    @staticmethod
    def get_chain_summary(chain: list) -> dict:
        if not chain:
            return {
                "depth": 0,
                "chain_trust": 0,
                "has_dangling": False,
                "terminal_provider": None,
                "terminal_type": None,
                "terminal_claimable": None,
                "providers_in_chain": [],
            }

        depth = len(chain)
        has_dangling = any(h.get("dangling") for h in chain)
        trust_values = [h.get("hop_trust", HOP_TRUST["Unknown"]) for h in chain]
        chain_trust = min(trust_values)

        non_dangling = [h for h in chain if not h.get("dangling")]
        terminal = non_dangling[-1] if non_dangling else chain[-1]

        providers = []
        seen = set()
        for h in chain:
            hint = h.get("provider_hint")
            if hint and hint not in seen:
                providers.append(hint)
                seen.add(hint)

        return {
            "depth": depth,
            "chain_trust": chain_trust,
            "has_dangling": has_dangling,
            "terminal_provider": terminal.get("provider_hint"),
            "terminal_type": terminal.get("provider_type"),
            "terminal_claimable": terminal.get("claimable"),
            "providers_in_chain": providers,
        }

    def analyze(self, domain: str) -> DNSInfo:
        info = DNSInfo()

        info.cname_chain = self.get_cname_chain(domain)

        if info.cname_chain:
            last_hop = info.cname_chain[-1]
            if last_hop.get("dangling"):
                info.dangling_cname = True

        a_records = self.resolve(domain, "A")
        if "__NXDOMAIN__" in a_records:
            info.nxdomain = True
        elif "__TIMEOUT__" not in a_records:
            info.a_records = a_records

        info.aaaa_records = [r for r in self.resolve(domain, "AAAA") if "__" not in r]
        info.mx_records   = [r for r in self.resolve(domain, "MX")   if "__" not in r]
        info.ns_records   = [r for r in self.resolve(domain, "NS")   if "__" not in r]
        info.txt_records  = [r for r in self.resolve(domain, "TXT")  if "__" not in r]

        return info

    @staticmethod
    def ns_resolves(ns: str) -> bool:
        try:
            socket.gethostbyname(ns.rstrip("."))
            return True
        except socket.gaierror:
            return False