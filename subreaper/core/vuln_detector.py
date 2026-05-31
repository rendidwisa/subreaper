from __future__ import annotations

import asyncio
import random
import re
import socket
import ssl
import string
from dataclasses import dataclass, field
from typing import Optional

import dns.exception
import dns.resolver

from subreaper.core.dns_analyzer import DNSAnalyzer
from subreaper.core.http_prober import HTTPProber
from subreaper.data.fingerprints import TAKEOVER_FINGERPRINTS, STRENGTH_SCORE
from subreaper.models import DNSInfo, VulnResult


# ── Thresholds ────────────────────────────────────────────────────────────────

NXDOMAIN_CONSENSUS_THRESHOLD = 2   # min resolvers agreeing on NXDOMAIN
MAX_CHAIN_DEPTH               = 15
WILDCARD_PROBE_LENGTH         = 18
TLS_TIMEOUT                   = 5
HTTP_RETRIES                  = 2
HTTP_RETRY_DELAY              = 0.4

SCORE_THRESHOLD_HIGH   = 80
SCORE_THRESHOLD_MEDIUM = 55

# Resolver pool used for multi-resolver consensus
_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# Signals that indicate the domain is actively served (not takeover-able)
_NEGATIVE_BODY_SIGNALS = [
    "parked domain",
    "buy this domain",
    "sedoparking",
    "domain for sale",
    "default nginx",
    "default apache",
    "welcome to cloudflare",
]


# ── Internal state ────────────────────────────────────────────────────────────

@dataclass
class _ResolverConsensus:
    nxdomain_votes: int = 0
    valid_votes: int   = 0
    timeout_votes: int = 0
    total: int         = 0

    @property
    def reached(self) -> bool:
        return (
            self.nxdomain_votes >= NXDOMAIN_CONSENSUS_THRESHOLD
            or self.valid_votes >= NXDOMAIN_CONSENSUS_THRESHOLD
        )

    @property
    def inconclusive(self) -> bool:
        return not self.reached and self.timeout_votes == self.total


@dataclass
class _TLSInfo:
    valid: bool        = False
    subject: str       = ""
    san: list          = field(default_factory=list)


@dataclass
class _HTTPResult:
    status: int                           = 0
    body_match: bool                      = False
    matched_fingerprint: str              = ""
    fingerprint_strength: int             = 0
    negative_signal: bool                 = False
    status_matches_provider: bool         = False


@dataclass
class _State:
    domain: str
    dns_info: DNSInfo
    provider: dict

    # Populated during pipeline
    last_cname_target: str                        = ""
    is_dangling: bool                             = False
    dangling_from: str                            = ""

    wildcard_detected: bool                       = False
    consensus: Optional[_ResolverConsensus]       = None
    http: Optional[_HTTPResult]                   = None
    tls: Optional[_TLSInfo]                       = None

    score: int                                    = 0
    evidence: list                                = field(default_factory=list)


# ── Detector ──────────────────────────────────────────────────────────────────

class VulnDetector:

    def __init__(self, dns_analyzer: DNSAnalyzer, http_prober: HTTPProber):
        self.dns  = dns_analyzer
        self.http = http_prober

    # ── Public entrypoint ─────────────────────────────────────────────────────

    async def check_takeover(
        self,
        domain: str,
        dns_info: DNSInfo,
    ) -> list[VulnResult]:

        findings: list[VulnResult] = []

        # Domain itself does not exist — nothing to take over
        if dns_info.nxdomain:
            return findings

        chain = dns_info.cname_chain or []

        # Step 1: validate chain structure
        last_target, is_dangling, dangling_from = self._parse_chain(chain)
        if not last_target:
            return findings

        # Step 2: identify provider from last valid CNAME target
        provider = self._match_provider(last_target)
        if not provider:
            return findings

        state = _State(
            domain=domain,
            dns_info=dns_info,
            provider=provider,
            last_cname_target=last_target,
            is_dangling=is_dangling,
            dangling_from=dangling_from,
        )
        state.evidence.append(f"CNAME_TARGET:{last_target}")
        state.evidence.append(f"PROVIDER:{provider['service']}")

        # Step 3: multi-resolver consensus on the CNAME target
        state.consensus = await self._resolver_consensus(last_target)

        if not state.consensus.reached and not state.consensus.inconclusive:
            # Resolvers disagree without timeout — likely false alarm
            return findings

        if state.consensus.inconclusive:
            state.evidence.append("CONSENSUS:INCONCLUSIVE(all_timeout)")
        else:
            state.evidence.append(
                f"CONSENSUS:NXDOMAIN={state.consensus.nxdomain_votes}/{state.consensus.total}"
            )

        # Step 4: wildcard DNS check — if wildcard exists, any subdomain resolves
        state.wildcard_detected = await self._has_wildcard(domain)
        if state.wildcard_detected:
            state.evidence.append("WILDCARD_DNS:skip")
            return findings

        # Step 5: HTTP probe + fingerprint matching
        state.http = await self._probe_http(domain, provider)

        # Step 6: TLS info (informational, adds score bonus)
        state.tls = await self._collect_tls(domain)

        # Step 7: score and build result
        self._score(state)

        result = self._build_result(state)
        if result:
            findings.append(result)

        # Step 8: independent NS takeover check
        findings.extend(self._check_ns_takeover(domain, dns_info))

        return findings

    # ── Chain parsing ─────────────────────────────────────────────────────────

    def _parse_chain(
        self,
        chain: list,
    ) -> tuple[str, bool, str]:
        """
        Walk the CNAME chain.
        Returns (last_valid_target, is_dangling, dangling_from).
        Returns ("", False, "") if chain is invalid.
        """
        if not chain or len(chain) > MAX_CHAIN_DEPTH:
            return "", False, ""

        visited: set[str] = set()
        last_valid = ""
        dangling_from = ""
        is_dangling = False

        for hop in chain:
            src = hop.get("from", "").lower().rstrip(".")
            dst = hop.get("to", "").lower().rstrip(".")

            if not src or not dst:
                return "", False, ""

            if src in visited:
                return "", False, ""     # loop detected
            visited.add(src)

            if hop.get("dangling"):
                # Only a real dangling if we had at least one valid hop before
                if last_valid:
                    is_dangling = True
                    dangling_from = src
                break

            last_valid = dst

        return last_valid, is_dangling, dangling_from

    # ── Provider matching ─────────────────────────────────────────────────────

    def _match_provider(self, cname_target: str) -> Optional[dict]:
        target = cname_target.lower().rstrip(".")
        for provider in TAKEOVER_FINGERPRINTS:
            for pattern in provider.get("cname_patterns", []):
                # Boundary-anchored match: prevents evilgithub.io matching github.io
                regex = rf"(?:^|\.){re.escape(pattern.lower().rstrip('.'))}$"
                if re.search(regex, target):
                    return provider
        return None

    # ── Multi-resolver consensus ──────────────────────────────────────────────

    async def _resolver_consensus(self, target: str) -> _ResolverConsensus:
        consensus = _ResolverConsensus(total=len(_RESOLVERS))

        loop = asyncio.get_event_loop()

        async def query(ns: str) -> str:
            def _resolve():
                r = dns.resolver.Resolver()
                r.nameservers = [ns]
                r.timeout = 3
                r.lifetime = 3
                try:
                    r.resolve(target, "A")
                    return "valid"
                except dns.resolver.NXDOMAIN:
                    return "nxdomain"
                except dns.resolver.Timeout:
                    return "timeout"
                except dns.exception.DNSException:
                    return "timeout"
            return await loop.run_in_executor(None, _resolve)

        results = await asyncio.gather(*[query(ns) for ns in _RESOLVERS])

        for r in results:
            if r == "nxdomain":
                consensus.nxdomain_votes += 1
            elif r == "valid":
                consensus.valid_votes += 1
            else:
                consensus.timeout_votes += 1

        return consensus

    # ── Wildcard detection ────────────────────────────────────────────────────

    async def _has_wildcard(self, domain: str) -> bool:
        probe = (
            "".join(random.choices(string.ascii_lowercase, k=WILDCARD_PROBE_LENGTH))
            + "."
            + domain
        )
        loop = asyncio.get_event_loop()
        info = await loop.run_in_executor(None, self.dns.analyze, probe)
        return bool(info.cname_chain or info.a_records)

    # ── HTTP probe ────────────────────────────────────────────────────────────

    async def _probe_http(self, domain: str, provider: dict) -> _HTTPResult:
        result = _HTTPResult()

        raw = None
        for _ in range(HTTP_RETRIES):
            raw = await self.http.probe(domain)
            if raw and "error" not in raw:
                break
            await asyncio.sleep(HTTP_RETRY_DELAY)

        if not raw or "error" in raw:
            return result

        result.status = raw.get("status", 0)
        body = raw.get("body", "").lower()

        # Negative signals — domain is actively served
        for signal in _NEGATIVE_BODY_SIGNALS:
            if signal in body:
                result.negative_signal = True
                break

        # Fingerprint matching
        for fp in provider.get("response_fingerprints", []):
            if isinstance(fp, dict):
                pattern  = fp.get("pattern", "").lower()
                strength = STRENGTH_SCORE.get(fp.get("strength", "LOW"), 30)
            else:
                pattern  = str(fp).lower()
                strength = STRENGTH_SCORE.get("MEDIUM", 50)

            if pattern and pattern in body:
                result.body_match           = True
                result.matched_fingerprint  = pattern
                result.fingerprint_strength = strength
                break

        # Status code agreement
        result.status_matches_provider = result.status in provider.get("http_codes", [])

        return result

    # ── TLS info ──────────────────────────────────────────────────────────────

    async def _collect_tls(self, domain: str) -> _TLSInfo:
        tls = _TLSInfo()

        def _handshake():
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=TLS_TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as s:
                        cert = s.getpeercert()
                        return {
                            "valid": True,
                            "subject": str(cert.get("subject", "")),
                            "san": [x[1] for x in cert.get("subjectAltName", []) if len(x) > 1],
                        }
            except Exception:
                return None

        loop = asyncio.get_event_loop()
        info = await loop.run_in_executor(None, _handshake)

        if info:
            tls.valid   = True
            tls.subject = info["subject"]
            tls.san     = info["san"]

        return tls

    # ── Scoring ───────────────────────────────────────────────────────────────

    def _score(self, state: _State) -> None:
        score = 0

        # Dangling CNAME is the strongest structural signal
        if state.is_dangling:
            score += 40
        elif state.consensus and state.consensus.nxdomain_votes >= NXDOMAIN_CONSENSUS_THRESHOLD:
            score += 30

        # Known provider match
        score += 20

        http = state.http
        if http:
            if http.body_match:
                score += min(http.fingerprint_strength, 25)

            if http.status_matches_provider and http.body_match:
                score += 10

            # Penalise contradicting signals
            if http.negative_signal:
                score -= 30

            if http.body_match and not http.status_matches_provider:
                score -= 10

        if state.tls and state.tls.valid:
            score += 5

        state.score = max(score, 0)

    # ── Result builder ────────────────────────────────────────────────────────

    def _build_result(self, state: _State) -> Optional[VulnResult]:
        if state.score < SCORE_THRESHOLD_MEDIUM:
            return None

        confidence = "HIGH" if state.score >= SCORE_THRESHOLD_HIGH else "MEDIUM"
        vuln_type  = "DANGLING_CNAME" if state.is_dangling else "SUBDOMAIN_TAKEOVER"

        evidence = list(state.evidence)
        if state.http and state.http.body_match:
            evidence.append(f"HTTP_FINGERPRINT:{state.http.matched_fingerprint}")
        if state.http:
            evidence.append(f"HTTP_STATUS:{state.http.status}")

        if vuln_type == "DANGLING_CNAME":
            details = (
                f"CNAME chain has a dangling hop: {state.dangling_from} "
                f"-> unresolved target. Score: {state.score}/100"
            )
            rec = (
                "Remove the dangling DNS record or reclaim the target resource. "
                "Ensure the provider account or domain cannot be registered externally."
            )
        else:
            details = (
                f"Takeover surface confirmed on {state.provider['service']}. "
                f"Score: {state.score}/100"
            )
            rec = (
                "Reclaim the cloud resource immediately or remove the DNS record. "
                "Review provider account ownership and deployment status."
            )

        return VulnResult(
            domain=state.domain,
            vuln_type=vuln_type,
            service=state.provider["service"],
            confidence=confidence,
            details=details,
            cname_chain=[
                f"{h['from']} -> {h['to']}"
                for h in state.dns_info.cname_chain
            ],
            evidence=evidence,
            http_status=state.http.status if state.http else None,
            recommendation=rec,
        )

    # ── NS takeover ───────────────────────────────────────────────────────────

    def _check_ns_takeover(
        self,
        domain: str,
        dns_info: DNSInfo,
    ) -> list[VulnResult]:
        results = []

        # Only check when domain is alive but its nameserver is not
        if dns_info.nxdomain or not dns_info.ns_records or dns_info.cname_chain:
            return results

        for ns in dns_info.ns_records:
            ns_host = ns.rstrip(".")
            try:
                socket.gethostbyname(ns_host)
            except socket.gaierror:
                results.append(VulnResult(
                    domain=domain,
                    vuln_type="NS_TAKEOVER",
                    service="DNS Nameserver",
                    confidence="HIGH",
                    details=f"NS record points to unresolvable nameserver: {ns_host}",
                    evidence=[f"NS_UNRESOLVED:{ns_host}"],
                    recommendation=(
                        "Replace or reclaim the affected authoritative nameserver immediately."
                    ),
                ))

        return results