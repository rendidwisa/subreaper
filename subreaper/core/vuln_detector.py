"""
Vulnerability detection module.

Orchestrates DNS + HTTP evidence to produce confirmed VulnResult objects.
Three detection paths:

  1. DANGLING_CNAME   — CNAME chain ends in NXDOMAIN (DNS-only, no HTTP needed)
  2. SUBDOMAIN_TAKEOVER — CNAME points to an unclaimed SaaS/cloud resource
                          (requires BOTH body fingerprint AND matching HTTP code)
  3. NS_TAKEOVER       — NS record points to an unresolvable nameserver
"""

from subreaper.core.dns_analyzer import DNSAnalyzer
from subreaper.core.http_prober import HTTPProber
from subreaper.data.fingerprints import TAKEOVER_FINGERPRINTS
from subreaper.models import DNSInfo, VulnResult


class VulnDetector:
    """
    Detects subdomain takeover and related DNS vulnerabilities.

    Designed for zero-false-positive output:
      - DANGLING_CNAME requires at least one valid hop before the NXDOMAIN.
      - SUBDOMAIN_TAKEOVER requires both a body fingerprint match *and* a
        matching HTTP status code — one condition alone is not enough.
      - NS_TAKEOVER only fires when the domain actually exists in DNS.
    """

    def __init__(self, dns_analyzer: DNSAnalyzer, http_prober: HTTPProber):
        self.dns  = dns_analyzer
        self.http = http_prober

    # ── private helpers ──────────────────────────────────────────────────────

    def _cname_matches_service(
        self, cname_chain: list, patterns: list
    ) -> tuple[bool, str | None]:
        """Return (True, matched_target) if any hop in *cname_chain* matches a pattern."""
        for hop in cname_chain:
            target = hop.get("to", "").lower()
            for pattern in patterns:
                if pattern.lower() in target:
                    return True, target
        return False, None

    def _body_matches_fingerprint(
        self, body: str, fingerprints: list
    ) -> tuple[bool, str | None]:
        """Return (True, matched_fingerprint) if *body* contains any fingerprint string."""
        body_lower = body.lower()
        for fp in fingerprints:
            if fp.lower() in body_lower:
                return True, fp
        return False, None

    # ── main detection entry point ───────────────────────────────────────────

    async def check_takeover(self, domain: str, dns_info: DNSInfo) -> list[VulnResult]:
        """
        Run all detection checks against *domain* / *dns_info*.

        Returns a (possibly empty) list of VulnResult objects.
        """
        vulns: list[VulnResult] = []

        # ── 1. DANGLING CNAME ────────────────────────────────────────────────
        # Verified at DNS level — no HTTP probe needed.
        if dns_info.dangling_cname and dns_info.cname_chain:
            valid_hops   = [h for h in dns_info.cname_chain if not h.get("dangling")]
            dangling_hop = next(
                (h for h in dns_info.cname_chain if h.get("dangling")), None
            )

            if valid_hops and dangling_hop:
                vuln = VulnResult(
                    domain=domain,
                    vuln_type="DANGLING_CNAME",
                    service="Unknown",
                    confidence="HIGH",
                    details=(
                        "Valid CNAME chain detected, but the final target does not exist. "
                        f"Target: {dangling_hop.get('to')}"
                    ),
                    cname_chain=[
                        f"{h['from']} → {h['to']}" for h in dns_info.cname_chain
                    ],
                    evidence=[
                        f"Last hop: {dangling_hop.get('from')} → NXDOMAIN",
                        "Target domain is not registered, can be claimed/register",
                    ],
                    recommendation=(
                        "Remove this CNAME record from your DNS settings, or register the target domain. "
                        "An attacker could claim the target domain to host malicious content."
                    ),
                )

                # Try to identify the service from the valid portion of the chain
                for fp_data in TAKEOVER_FINGERPRINTS:
                    match, _ = self._cname_matches_service(
                        valid_hops, fp_data["cname_patterns"]
                    )
                    if match:
                        vuln.service     = fp_data["service"]
                        vuln.confidence  = fp_data["confidence"]
                        break

                vulns.append(vuln)
                return vulns   # DANGLING_CNAME found — skip remaining checks

        # ── 2. CNAME → SERVICE TAKEOVER ──────────────────────────────────────
        # Requires matching CNAME pattern AND (body fingerprint + HTTP status).
        if dns_info.cname_chain and not dns_info.dangling_cname:
            for fp_data in TAKEOVER_FINGERPRINTS:
                match, matched_cname = self._cname_matches_service(
                    dns_info.cname_chain, fp_data["cname_patterns"]
                )
                if not match:
                    continue

                # HTTP probe — mandatory for this check
                http_resp = await self.http.probe(domain)
                if not http_resp or "error" in http_resp:
                    continue

                status = http_resp.get("status", 0)
                body   = http_resp.get("body", "")

                body_match, matched_fp = self._body_matches_fingerprint(
                    body, fp_data["response_fingerprints"]
                )

                # BOTH conditions must be true — prevents false positives
                if body_match and status in fp_data["http_codes"]:
                    vuln = VulnResult(
                        domain=domain,
                        vuln_type="SUBDOMAIN_TAKEOVER",
                        service=fp_data["service"],
                        confidence=fp_data["confidence"],
                        details=(
                            f"CNAME to {fp_data['service']} points to an unclaimed resource"
                        ),
                        cname_chain=[
                            f"{h['from']} → {h['to']}" for h in dns_info.cname_chain
                        ],
                        evidence=[
                            f"CNAME target: {matched_cname}",
                            f"HTTP {status} + fingerprint: '{matched_fp}'",
                        ],
                        http_status=status,
                        recommendation=(
                            f"Claim the {fp_data['service']} resource pointed to by the CNAME, "
                            f"or remove this DNS record. Ref: {fp_data['references']}"
                        ),
                    )
                    vulns.append(vuln)

        # ── 3. NS TAKEOVER ────────────────────────────────────────────────────
        # Only relevant when domain EXISTS in DNS (has NS records, no CNAME chain).
        if not dns_info.nxdomain and dns_info.ns_records and not dns_info.cname_chain:
            for ns in dns_info.ns_records:
                if not DNSAnalyzer.ns_resolves(ns):
                    vuln = VulnResult(
                        domain=domain,
                        vuln_type="NS_TAKEOVER",
                        service="DNS Nameserver",
                        confidence="HIGH",
                        details=(
                            f"NS record points to a nameserver that does not resolve: {ns}"
                        ),
                        evidence=[f"NS: {ns} → does not resolve"],
                        recommendation="Claim or replace the NS record",
                    )
                    vulns.append(vuln)

        return vulns