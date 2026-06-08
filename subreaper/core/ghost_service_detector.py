from __future__ import annotations

import re
from typing import Optional

from subreaper.data.fingerprints import TAKEOVER_FINGERPRINTS, STRENGTH_SCORE
from subreaper.models import DNSInfo, GhostService

from subreaper.data.ghost_service_signals import (
    SSO_SIGNALS,
    FOR_SALE_SIGNALS,
    PROBE_HEADERS,
    TLD_BRAND_HINTS,
)

# ── Detector ──────────────────────────────────────────────────────────────────

class GhostServiceDetector:

    def __init__(self, http_prober):
        self.http = http_prober

    # ── Public entrypoint ─────────────────────────────────────────────────────

    async def detect(
        self,
        domain:   str,
        dns_info: DNSInfo,
    ) -> list[GhostService]:
        """
        Returns GhostService entries where a live external provider is
        serving content that carries no trace of the target's identity.
        """
        target = self._last_cname_target(dns_info)
        if not target:
            return []

        provider = self._match_provider(target)
        if not provider:
            return []

        raw = await self.http.probe(domain, extra_headers=PROBE_HEADERS)
        if not raw or "error" in raw:
            return []

        status = raw.get("status", 0)
        body   = raw.get("body", "")

        if self._is_sso_redirect(body):
            return []

        provider_hit  = self._check_provider_fingerprint(body, provider)
        identity_hit  = self._check_target_identity(body, domain)

        if not provider_hit or identity_hit:
            return []

        severity = self._score_severity(status, body, provider)
        rec      = self._recommendation(provider["service"], status, body)

        return [GhostService(
            domain=domain,
            cname_target=target,
            provider=provider["service"],
            http_status=status,
            severity=severity,
            evidence=self._build_evidence(provider_hit, body, domain),
            recommendation=rec,
        )]

    # ── Step 1: extract last CNAME target ────────────────────────────────────

    @staticmethod
    def _last_cname_target(dns_info: DNSInfo) -> str:
        chain = dns_info.cname_chain or []
        if not chain:
            return ""
        last = chain[-1]
        if isinstance(last, dict):
            return last.get("to", "").lower().rstrip(".")
        return getattr(last, "to", "").lower().rstrip(".")

    # ── Step 2: provider match ────────────────────────────────────────────────

    @staticmethod
    def _match_provider(cname_target: str) -> Optional[dict]:
        for provider in TAKEOVER_FINGERPRINTS:
            for pattern in provider.get("cname_patterns", []):
                regex = rf"(?:^|\.){re.escape(pattern.lower().rstrip('.'))}$"
                if re.search(regex, cname_target):
                    return provider
        return None

    # ── Step 3: fingerprint + identity checks ────────────────────────────────

    @staticmethod
    def _check_provider_fingerprint(body: str, provider: dict) -> list[str]:
        body_lower = body.lower()
        matched    = []
        for fp in provider.get("response_fingerprints", []):
            pattern = (fp.get("pattern", "") if isinstance(fp, dict) else str(fp)).lower()
            if pattern and pattern in body_lower:
                matched.append(pattern)
        return matched

    @staticmethod
    def _check_target_identity(body: str, domain: str) -> bool:
        body_lower = body.lower()
        for kw in GhostServiceDetector._target_keywords(domain):
            if kw in body_lower:
                return True
        return False

    # ── Step 4: severity scoring ──────────────────────────────────────────────

    @staticmethod
    def _score_severity(status: int, body: str, provider: dict) -> int:
        body_lower = body.lower()
        service    = provider.get("service", "").lower()

        if "nosuchbucket" in body_lower or "the specified bucket does not exist" in body_lower:
            return 95
        if "404" in body_lower and "github" in service:
            return 95
        if status == 404:
            return 90
        if status == 200:
            if any(s in body_lower for s in FOR_SALE_SIGNALS):
                return 60
            return 85
        if status in (301, 302):
            return 50
        if status == 403:
            return 45
        if status == 503:
            return 40
        return 30

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _target_keywords(domain: str) -> list[str]:
        parts = domain.lower().rstrip(".").split(".")
        if len(parts) < 2:
            return [parts[0]]

        sld = parts[-2]
        tld = parts[-1]

        keywords = [sld, f"{sld}.{tld}", f"{sld} {tld}"]

        _tld_brand_hints: dict[str, str] = {
            "it": "italia", "de": "deutschland", "fr": "france",
            "es": "españa",  "br": "brasil",      "jp": "japan",
            "cn": "china",   "au": "australia",   "nl": "nederland",
        }
        if tld in _tld_brand_hints:
            keywords.append(f"{sld} {_tld_brand_hints[tld]}")

        return keywords

    @staticmethod
    def _is_sso_redirect(body: str) -> bool:
        body_lower = body.lower()
        return any(s in body_lower for s in SSO_SIGNALS)

    @staticmethod
    def _build_evidence(matched_patterns: list[str], body: str, domain: str) -> list[str]:
        identity_found = GhostServiceDetector._check_target_identity(body, domain)
        return [
            f"PROVIDER_FP_MATCH:{','.join(matched_patterns)}",
            f"TARGET_IDENTITY:{'FOUND' if identity_found else 'NOT_FOUND'}",
            f"BODY_PREVIEW:{body[:200]}",
        ]

    @staticmethod
    def _recommendation(service: str, status: int, body: str) -> str:
        body_lower  = body.lower()
        svc         = service.lower()

        if "nosuchbucket" in body_lower or "bucket" in svc:
            return (
                "S3 not found. remove CNAME record "
                "atau buat ulang bucket sebelum diklaim pihak lain."
            )
        if "github" in svc and status == 404:
            return "GitHub Pages repository tidak ditemukan. Hapus CNAME record atau buat ulang repository."
        if "heroku" in svc and status == 404:
            return "Heroku app tidak ditemukan. Hapus CNAME record atau buat ulang app."
        if "netlify" in svc and status == 404:
            return "Netlify site tidak ditemukan. Hapus CNAME record atau reclaim site."
        return (
            f"CNAME masih pointing ke {service} tapi konten tidak mencerminkan identitas target. "
            "Verifikasi kepemilikan resource dan hapus record jika sudah tidak digunakan."
        )