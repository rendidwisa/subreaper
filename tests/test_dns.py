"""
Unit tests for DNSAnalyzer.

All external DNS calls are mocked — no network required.
"""

import pytest
import dns.resolver
import dns.exception

from unittest.mock import MagicMock, patch
from subreaper.core.dns_analyzer import DNSAnalyzer


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def analyzer():
    return DNSAnalyzer(nameservers=["8.8.8.8"], timeout=5)


# ─────────────────────────────────────────────────────────────────────────────
# get_cname_chain
# ─────────────────────────────────────────────────────────────────────────────

class TestGetCNAMEChain:
    """
    Core anti-false-positive logic lives here.
    Every case from the docstring is covered.
    """

    def test_nxdomain_on_origin_returns_empty_chain(self, analyzer):
        """Case 1: origin domain itself is NXDOMAIN → empty chain, not dangling."""
        with patch.object(analyzer.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN):
            chain = analyzer.get_cname_chain("nope.example.com")

        assert chain == [], "NXDOMAIN on origin must return an empty chain"

    def test_nxdomain_on_target_marks_dangling(self, analyzer):
        """Case 2: first hop succeeds, target NXDOMAIN → dangling = True."""
        first_answer  = MagicMock()
        first_answer.__str__ = lambda self: "old.github.io."

        def side_effect(domain, rdtype):
            if domain == "sub.example.com":
                return [first_answer]
            raise dns.resolver.NXDOMAIN

        with patch.object(analyzer.resolver, "resolve", side_effect=side_effect):
            chain = analyzer.get_cname_chain("sub.example.com")

        assert len(chain) == 2
        assert chain[0] == {"from": "sub.example.com", "to": "old.github.io"}
        assert chain[1].get("dangling") is True
        assert "__NXDOMAIN__" in chain[1]["to"]

    def test_no_cname_record_returns_empty_chain(self, analyzer):
        """Case 3: domain has no CNAME record → empty chain (normal A record)."""
        with patch.object(analyzer.resolver, "resolve", side_effect=dns.resolver.NoAnswer):
            chain = analyzer.get_cname_chain("www.example.com")

        assert chain == []

    def test_multi_hop_chain_resolved(self, analyzer):
        """Three-hop CNAME chain where all targets exist."""
        hops = [
            ("a.example.com", "b.example.com."),
            ("b.example.com", "c.example.com."),
        ]

        def side_effect(domain, rdtype):
            for src, dst in hops:
                if domain == src:
                    m = MagicMock()
                    m.__str__ = lambda self, d=dst: d
                    return [m]
            raise dns.resolver.NoAnswer

        with patch.object(analyzer.resolver, "resolve", side_effect=side_effect):
            chain = analyzer.get_cname_chain("a.example.com")

        assert len(chain) == 2
        assert chain[0]["from"] == "a.example.com"
        assert chain[0]["to"]   == "b.example.com"
        assert chain[1]["from"] == "b.example.com"
        assert chain[1]["to"]   == "c.example.com"

    def test_cycle_protection(self, analyzer):
        """Circular CNAME references must not cause infinite loops."""
        answer = MagicMock()
        answer.__str__ = lambda self: "a.example.com."

        with patch.object(analyzer.resolver, "resolve", return_value=[answer]):
            chain = analyzer.get_cname_chain("a.example.com")

        # The visited-set breaks the cycle after one hop is recorded.
        # What matters: the chain is finite (no infinite loop) and has no
        # dangling marker (a self-referencing CNAME is not a takeover).
        assert len(chain) <= 1
        dangling_hops = [h for h in chain if h.get("dangling")]
        assert dangling_hops == [], "Self-referencing CNAME must not be marked dangling"


# ─────────────────────────────────────────────────────────────────────────────
# analyze — dangling_cname flag
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyze:
    def test_dangling_cname_flag_set(self, analyzer):
        """analyze() must set dangling_cname=True when chain ends in NXDOMAIN."""
        first_answer = MagicMock()
        first_answer.__str__ = lambda self: "old.github.io."

        call_count = {"n": 0}

        def side_effect(domain, rdtype):
            if rdtype == "CNAME":
                if call_count["n"] == 0:
                    call_count["n"] += 1
                    return [first_answer]
                raise dns.resolver.NXDOMAIN
            raise dns.resolver.NoAnswer

        with patch.object(analyzer.resolver, "resolve", side_effect=side_effect):
            info = analyzer.analyze("sub.example.com")

        assert info.dangling_cname is True

    def test_ns_resolves_true_for_valid_host(self):
        with patch("socket.gethostbyname", return_value="93.184.216.34"):
            assert DNSAnalyzer.ns_resolves("ns1.example.com") is True

    def test_ns_resolves_false_for_invalid_host(self):
        import socket
        with patch("socket.gethostbyname", side_effect=socket.gaierror):
            assert DNSAnalyzer.ns_resolves("ns1.ghost-domain.xyz") is False