"""
Unit tests for VulnDetector.

HTTP calls are fully mocked — no network required.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from subreaper.core.dns_analyzer import DNSAnalyzer
from subreaper.core.http_prober import HTTPProber
from subreaper.core.vuln_detector import VulnDetector
from subreaper.models import DNSInfo


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def detector():
    dns_mock  = MagicMock(spec=DNSAnalyzer)
    http_mock = MagicMock(spec=HTTPProber)
    return VulnDetector(dns_mock, http_mock)


def _dns_info(**kwargs) -> DNSInfo:
    """Helper: build a DNSInfo with sane defaults, override via kwargs."""
    defaults = dict(
        a_records=[],
        aaaa_records=[],
        cname_chain=[],
        mx_records=[],
        ns_records=[],
        txt_records=[],
        nxdomain=False,
        servfail=False,
        dangling_cname=False,
    )
    defaults.update(kwargs)
    return DNSInfo(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# DANGLING_CNAME detection
# ─────────────────────────────────────────────────────────────────────────────

class TestDanglingCNAME:
    @pytest.mark.asyncio
    async def test_dangling_cname_detected(self, detector):
        """A valid first hop + dangling target → DANGLING_CNAME vuln."""
        dns_info = _dns_info(
            dangling_cname=True,
            cname_chain=[
                {"from": "sub.example.com", "to": "old.github.io"},
                {"from": "old.github.io",   "to": "__NXDOMAIN__ (target tidak ada!)", "dangling": True},
            ],
        )

        vulns = await detector.check_takeover("sub.example.com", dns_info)

        assert len(vulns) == 1
        assert vulns[0].vuln_type == "DANGLING_CNAME"
        assert vulns[0].confidence == "HIGH"

    @pytest.mark.asyncio
    async def test_dangling_cname_identifies_github_pages(self, detector):
        """Service should be identified as GitHub Pages from the valid CNAME hop."""
        dns_info = _dns_info(
            dangling_cname=True,
            cname_chain=[
                {"from": "sub.example.com", "to": "user.github.io"},
                {"from": "user.github.io",  "to": "__NXDOMAIN__ (target tidak ada!)", "dangling": True},
            ],
        )

        vulns = await detector.check_takeover("sub.example.com", dns_info)

        assert vulns[0].service == "GitHub Pages"

    @pytest.mark.asyncio
    async def test_no_valid_hops_before_nxdomain_is_ignored(self, detector):
        """
        If the dangling_cname flag is set but there are no valid hops before it,
        the detector must NOT produce a false positive.
        """
        dns_info = _dns_info(
            dangling_cname=True,
            cname_chain=[
                # Only the dangling hop, no valid first hop
                {"from": "sub.example.com", "to": "__NXDOMAIN__ (target tidak ada!)", "dangling": True},
            ],
        )

        vulns = await detector.check_takeover("sub.example.com", dns_info)

        assert vulns == []


# ─────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN_TAKEOVER detection (HTTP fingerprint path)
# ─────────────────────────────────────────────────────────────────────────────

class TestSubdomainTakeover:
    @pytest.mark.asyncio
    async def test_github_pages_takeover_detected(self, detector):
        """Both CNAME match AND body fingerprint + 404 → SUBDOMAIN_TAKEOVER."""
        dns_info = _dns_info(
            cname_chain=[{"from": "sub.example.com", "to": "user.github.io"}],
        )
        detector.http.probe = AsyncMock(return_value={
            "status": 404,
            "url":    "https://sub.example.com",
            "body":   "There isn't a GitHub Pages site here.",
            "headers": {},
        })

        vulns = await detector.check_takeover("sub.example.com", dns_info)

        assert len(vulns) == 1
        assert vulns[0].vuln_type == "SUBDOMAIN_TAKEOVER"
        assert vulns[0].service   == "GitHub Pages"
        assert vulns[0].http_status == 404

    @pytest.mark.asyncio
    async def test_body_match_without_correct_status_code_is_ignored(self, detector):
        """Body fingerprint match alone (wrong status) must NOT trigger a finding."""
        dns_info = _dns_info(
            cname_chain=[{"from": "sub.example.com", "to": "user.github.io"}],
        )
        detector.http.probe = AsyncMock(return_value={
            "status": 200,   # ← wrong status code
            "url":    "https://sub.example.com",
            "body":   "There isn't a GitHub Pages site here.",
            "headers": {},
        })

        vulns = await detector.check_takeover("sub.example.com", dns_info)

        assert vulns == []

    @pytest.mark.asyncio
    async def test_correct_status_without_body_fingerprint_is_ignored(self, detector):
        """HTTP 404 without a fingerprint match must NOT trigger a finding."""
        dns_info = _dns_info(
            cname_chain=[{"from": "sub.example.com", "to": "user.github.io"}],
        )
        detector.http.probe = AsyncMock(return_value={
            "status": 404,
            "url":    "https://sub.example.com",
            "body":   "Some random 404 page without fingerprint text",
            "headers": {},
        })

        vulns = await detector.check_takeover("sub.example.com", dns_info)

        assert vulns == []

    @pytest.mark.asyncio
    async def test_http_error_skips_fingerprint_check(self, detector):
        """Connection error during HTTP probe must not produce a false positive."""
        dns_info = _dns_info(
            cname_chain=[{"from": "sub.example.com", "to": "user.github.io"}],
        )
        detector.http.probe = AsyncMock(return_value={"error": "timeout"})

        vulns = await detector.check_takeover("sub.example.com", dns_info)

        assert vulns == []

    @pytest.mark.asyncio
    async def test_aws_s3_takeover_detected(self, detector):
        """AWS S3 NoSuchBucket response → SUBDOMAIN_TAKEOVER."""
        dns_info = _dns_info(
            cname_chain=[{"from": "static.example.com", "to": "mybucket.s3.amazonaws.com"}],
        )
        detector.http.probe = AsyncMock(return_value={
            "status": 404,
            "url":    "https://static.example.com",
            "body":   "<Error><Code>NoSuchBucket</Code></Error>",
            "headers": {},
        })

        vulns = await detector.check_takeover("static.example.com", dns_info)

        assert len(vulns) == 1
        assert vulns[0].service == "AWS S3"


# ─────────────────────────────────────────────────────────────────────────────
# NS_TAKEOVER detection
# ─────────────────────────────────────────────────────────────────────────────

class TestNSTakeover:
    @pytest.mark.asyncio
    async def test_ns_takeover_unresolvable_nameserver(self, detector):
        """NS record pointing to an unresolvable host → NS_TAKEOVER."""
        dns_info = _dns_info(
            ns_records=["ns1.ghost-registrar.xyz"],
            nxdomain=False,
        )

        with patch.object(DNSAnalyzer, "ns_resolves", return_value=False):
            vulns = await detector.check_takeover("example.com", dns_info)

        assert len(vulns) == 1
        assert vulns[0].vuln_type == "NS_TAKEOVER"

    @pytest.mark.asyncio
    async def test_ns_takeover_not_triggered_when_ns_resolves(self, detector):
        """Resolvable NS must not produce a finding."""
        dns_info = _dns_info(
            ns_records=["ns1.example.com"],
            nxdomain=False,
        )

        with patch.object(DNSAnalyzer, "ns_resolves", return_value=True):
            vulns = await detector.check_takeover("example.com", dns_info)

        assert vulns == []

    @pytest.mark.asyncio
    async def test_ns_takeover_skipped_when_nxdomain(self, detector):
        """NS takeover check is skipped when the domain itself is NXDOMAIN."""
        dns_info = _dns_info(
            ns_records=["ns1.ghost-registrar.xyz"],
            nxdomain=True,   # ← domain doesn't exist
        )

        with patch.object(DNSAnalyzer, "ns_resolves", return_value=False):
            vulns = await detector.check_takeover("example.com", dns_info)

        assert vulns == []

    @pytest.mark.asyncio
    async def test_ns_takeover_skipped_when_cname_chain_present(self, detector):
        """NS takeover check is skipped when a CNAME chain exists."""
        dns_info = _dns_info(
            cname_chain=[{"from": "sub.example.com", "to": "app.github.io"}],
            ns_records=["ns1.ghost-registrar.xyz"],
        )
        detector.http.probe = AsyncMock(return_value={"error": "timeout"})

        with patch.object(DNSAnalyzer, "ns_resolves", return_value=False):
            vulns = await detector.check_takeover("sub.example.com", dns_info)

        ns_vulns = [v for v in vulns if v.vuln_type == "NS_TAKEOVER"]
        assert ns_vulns == []