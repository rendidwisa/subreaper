"""
DNS analysis module.

Handles resolution, CNAME chain traversal, and provider classification.
Each hop is enriched with provider metadata and a trust score.
"""

from __future__ import annotations

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
    "SaaS":     85,
    "CDN":      80,
    "Cloud":    75,
    "Unknown":  40,
    "Dangling": 0,
}


class DNSAnalyzer:

    DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    MAX_CNAME_HOPS = 15

    def __init__(self, nameservers: list = None, timeout: int = 5):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout  = timeout
        self.resolver.lifetime = timeout
        self.resolver.nameservers = nameservers or self.DEFAULT_NAMESERVERS
        self._provider_map = self._build_provider_map()

    # ── Provider map ──────────────────────────────────────────────────────────

    @staticmethod
    def _build_provider_map() -> list[dict]:
        entries = []
        for fp in TAKEOVER_FINGERPRINTS + _SUPPLEMENTARY_PROVIDERS:
            entries.append({
                "patterns":       fp["cname_patterns"],
                "service":        fp["service"],
                "provider_type":  fp.get("provider_type", "Unknown"),
                "provider_group": fp.get("provider_group", "Unknown"),
                "claimable":      fp.get("claimable"),
                "risk_weight":    fp.get("risk_weight", 50),
            })
        return entries

    @staticmethod
    def _matches_domain_boundary(target: str, pattern: str) -> bool:
        t = target.lower().rstrip(".")
        p = pattern.lower().rstrip(".")
        return bool(re.search(r"(?:^|\.)" + re.escape(p) + r"(?:\.|$)", t))

    def _classify_target(self, target: str) -> dict:
        normalized = target.lower().rstrip(".")
        for entry in self._provider_map:
            for pattern in entry["patterns"]:
                if self._matches_domain_boundary(normalized, pattern):
                    ptype = entry["provider_type"]
                    return {
                        "provider_hint":    entry["service"],
                        "provider_type":    ptype,
                        "provider_group":   entry["provider_group"],
                        "is_cloud_provider": ptype in ("Cloud", "CDN"),
                        "claimable":        entry["claimable"],
                        "hop_trust":        HOP_TRUST.get(ptype, HOP_TRUST["Unknown"]),
                    }
        return {
            "provider_hint":    None,
            "provider_type":    "Unknown",
            "provider_group":   None,
            "is_cloud_provider": False,
            "claimable":        None,
            "hop_trust":        HOP_TRUST["Unknown"],
        }

    # ── Resolution helpers ────────────────────────────────────────────────────

    def resolve(self, domain: str, rdtype: str) -> list:
        try:
            return [str(r) for r in self.resolver.resolve(domain, rdtype)]
        except dns.resolver.NXDOMAIN:
            return ["__NXDOMAIN__"]
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.Timeout:
            return ["__TIMEOUT__"]
        except dns.exception.DNSException:
            return []

    def _target_resolves(self, target: str) -> bool:
        """
        Return True if *target* has at least one A or AAAA record.

        NoAnswer is treated the same as NXDOMAIN — the target exists in DNS
        but has no address records, meaning it cannot serve traffic and is
        therefore dangling for takeover purposes.
        """
        for rdtype in ("A", "AAAA"):
            try:
                answers = self.resolver.resolve(target, rdtype)
                if answers:
                    return True
            except dns.resolver.NXDOMAIN:
                return False
            except dns.resolver.NoAnswer:
                continue        # try next record type
            except (dns.resolver.Timeout, dns.exception.DNSException):
                return True     # inconclusive — assume alive, avoid false positive
        return False

    # ── CNAME chain traversal ─────────────────────────────────────────────────

    def get_cname_chain(self, domain: str) -> list:
        """
        Follow the CNAME chain from *domain* up to MAX_CNAME_HOPS hops.

        Each hop dict contains:
          from, to, provider_hint, provider_type, provider_group,
          is_cloud_provider, claimable, hop_trust, [dangling]

        A hop is marked dangling=True when its target (the "to" field) does
        not resolve to any address record (A or AAAA) — including the case
        where the target exists in DNS but has no address records (NoAnswer).
        """
        chain     = []
        current   = domain
        visited: set[str] = set()
        hop_count = 0
        remaining = self.MAX_CNAME_HOPS

        while remaining > 0:
            if current in visited:
                break
            visited.add(current)

            try:
                answers = self.resolver.resolve(current, "CNAME")
                target  = str(list(answers)[0]).rstrip(".")

                hop = {"from": current, "to": target}
                hop.update(self._classify_target(target))

                if not self._target_resolves(target):
                    hop["dangling"]  = True
                    hop["hop_trust"] = HOP_TRUST["Dangling"]
                    chain.append(hop)
                    break           # stop — no point following a dead end

                chain.append(hop)
                current    = target
                hop_count += 1
                remaining -= 1

            except dns.resolver.NXDOMAIN:
                # current itself does not exist
                if hop_count == 0:
                    return []       # origin domain absent — not a CNAME issue
                # We followed at least one valid hop before hitting NXDOMAIN
                chain.append({
                    "from":            current,
                    "to":              "NXDOMAIN",
                    "dangling":        True,
                    "provider_hint":   None,
                    "provider_type":   "Unknown",
                    "provider_group":  None,
                    "is_cloud_provider": False,
                    "claimable":       None,
                    "hop_trust":       HOP_TRUST["Dangling"],
                })
                break

            except (dns.resolver.NoAnswer, dns.exception.DNSException):
                break   # no CNAME record — end of chain

        return chain

    # ── Chain summary ─────────────────────────────────────────────────────────

    @staticmethod
    def get_chain_summary(chain: list) -> dict:
        if not chain:
            return {
                "depth":             0,
                "chain_trust":       0,
                "has_dangling":      False,
                "terminal_provider": None,
                "terminal_type":     None,
                "terminal_claimable": None,
                "providers_in_chain": [],
            }

        has_dangling  = any(h.get("dangling") for h in chain)
        trust_values  = [h.get("hop_trust", HOP_TRUST["Unknown"]) for h in chain]
        non_dangling  = [h for h in chain if not h.get("dangling")]
        terminal      = non_dangling[-1] if non_dangling else chain[-1]

        providers: list[str] = []
        seen: set[str] = set()
        for h in chain:
            hint = h.get("provider_hint")
            if hint and hint not in seen:
                providers.append(hint)
                seen.add(hint)

        return {
            "depth":              len(chain),
            "chain_trust":        min(trust_values),
            "has_dangling":       has_dangling,
            "terminal_provider":  terminal.get("provider_hint"),
            "terminal_type":      terminal.get("provider_type"),
            "terminal_claimable": terminal.get("claimable"),
            "providers_in_chain": providers,
        }

    # ── Full domain analysis ──────────────────────────────────────────────────

    def analyze(self, domain: str) -> DNSInfo:
        info = DNSInfo()

        info.cname_chain = self.get_cname_chain(domain)

        if info.cname_chain and info.cname_chain[-1].get("dangling"):
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

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def ns_resolves(ns: str) -> bool:
        try:
            socket.gethostbyname(ns.rstrip("."))
            return True
        except socket.gaierror:
            return False