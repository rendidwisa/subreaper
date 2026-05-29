"""
DNS analysis module.

Handles all DNS resolution and CNAME chain traversal with anti-false-positive
logic baked into get_cname_chain().
"""

import socket

import dns.exception
import dns.resolver

from subreaper.models import DNSInfo


class DNSAnalyzer:
    """
    Resolves DNS records and builds CNAME chains for a given domain.

    Anti-false-positive CNAME logic
    ────────────────────────────────────────────────────────────────────
    Case 1 — NXDOMAIN on the FIRST domain (hop_count == 0)
        The origin domain itself doesn't exist in DNS.
        → NOT a dangling CNAME, NOT a takeover candidate.
        → Return empty chain.

    Case 2 — NXDOMAIN on an INTERMEDIATE hop (hop_count >= 1)
        A valid CNAME points to a target that no longer exists.
        → THIS is a dangling CNAME — takeover candidate.

    Case 3 — NoAnswer on a CNAME query
        The domain exists but has no CNAME record.
        → Normal end of chain, not a problem.
    ────────────────────────────────────────────────────────────────────
    """

    DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    MAX_CNAME_HOPS = 15

    def __init__(self, nameservers: list = None, timeout: int = 5):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        self.resolver.nameservers = nameservers or self.DEFAULT_NAMESERVERS

    # ── low-level helpers ────────────────────────────────────────────────────

    def resolve(self, domain: str, rdtype: str) -> list:
        """
        Resolve *domain* for *rdtype*.

        Returns a list of string records, or sentinel strings:
          "__NXDOMAIN__"  — domain does not exist
          "__TIMEOUT__"   — query timed out
        """
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

    # ── CNAME chain ──────────────────────────────────────────────────────────

    def get_cname_chain(self, domain: str) -> list:
        """
        Follow the full CNAME chain from *domain* until the end or an NXDOMAIN.

        Each element in the returned list is a dict:
            {"from": str, "to": str}
        or, for a dangling hop:
            {"from": str, "to": str, "dangling": True}

        Returns an empty list when the origin domain itself is NXDOMAIN (Case 1).
        """
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
                chain.append({"from": current, "to": target})
                current = target
                hop_count += 1
                remaining -= 1

            except dns.resolver.NXDOMAIN:
                if hop_count == 0:
                    # Origin domain itself doesn't exist — not a CNAME issue
                    return []
                # Target of a valid CNAME doesn't exist → dangling!
                chain.append({
                    "from": current,
                    "to": "__NXDOMAIN__ (target does not resolve!)",
                    "dangling": True,
                })
                break

            except dns.resolver.NoAnswer:
                # No CNAME record here — normal end of chain
                break

            except dns.exception.DNSException:
                break

        return chain

    # ── full analysis ────────────────────────────────────────────────────────

    def analyze(self, domain: str) -> DNSInfo:
        """
        Perform a comprehensive DNS analysis for *domain*.

        Resolves A, AAAA, CNAME chain, MX, NS, and TXT records.
        Sets dangling_cname and nxdomain flags on the returned DNSInfo.
        """
        info = DNSInfo()

        # CNAME chain first — most important for takeover detection
        info.cname_chain = self.get_cname_chain(domain)

        if info.cname_chain:
            last_hop = info.cname_chain[-1]
            if last_hop.get("dangling") or "__NXDOMAIN__" in last_hop.get("to", ""):
                info.dangling_cname = True

        # A records (also sets nxdomain flag)
        a_records = self.resolve(domain, "A")
        if "__NXDOMAIN__" in a_records:
            info.nxdomain = True
        elif "__TIMEOUT__" not in a_records:
            info.a_records = a_records

        # Remaining record types — strip sentinel values
        info.aaaa_records = [r for r in self.resolve(domain, "AAAA") if "__" not in r]
        info.mx_records   = [r for r in self.resolve(domain, "MX")   if "__" not in r]
        info.ns_records   = [r for r in self.resolve(domain, "NS")   if "__" not in r]
        info.txt_records  = [r for r in self.resolve(domain, "TXT")  if "__" not in r]

        return info

    # ── NS reachability helper (used by VulnDetector) ────────────────────────

    @staticmethod
    def ns_resolves(ns: str) -> bool:
        """Return True if *ns* resolves to at least one IP address."""
        try:
            socket.gethostbyname(ns.rstrip("."))
            return True
        except socket.gaierror:
            return False