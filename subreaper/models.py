"""
Data models used across SubReaper.

All dataclasses are defined here to avoid circular imports between modules.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DNSInfo:
    """Result of a full DNS analysis for a single domain."""

    a_records: list = field(default_factory=list)
    aaaa_records: list = field(default_factory=list)
    cname_chain: list = field(default_factory=list)
    mx_records: list = field(default_factory=list)
    ns_records: list = field(default_factory=list)
    txt_records: list = field(default_factory=list)
    nxdomain: bool = False
    servfail: bool = False
    dangling_cname: bool = False


@dataclass
class VulnResult:
    """A single confirmed vulnerability finding."""

    domain: str
    vuln_type: str          # SUBDOMAIN_TAKEOVER | DANGLING_CNAME | NS_TAKEOVER
    service: str
    confidence: str         # HIGH | MEDIUM
    details: str
    cname_chain: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    http_status: Optional[int] = None
    recommendation: str = ""


@dataclass
class ScanResult:
    """Aggregated result for one scanned domain."""

    domain: str
    timestamp: str
    dns: Optional[DNSInfo] = None
    vulnerabilities: list = field(default_factory=list)
    status: str = "CLEAN"   # CLEAN | VULNERABLE | NXDOMAIN
    scan_time_ms: float = 0.0