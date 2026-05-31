from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DNSInfo:
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
    domain: str
    vuln_type: str
    service: str
    confidence: str
    details: str
    cname_chain: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    http_status: Optional[int] = None
    recommendation: str = ""

    risk_score: int = 0
    exploitability: str = "NONE"
    verification_stage: str = "DNS"
    provider: str = ""
    is_claimable: bool = False
    evidence_level: str = "WEAK"


@dataclass
class ScanResult:
    domain: str
    timestamp: str
    dns: Optional[DNSInfo] = None
    vulnerabilities: list = field(default_factory=list)
    status: str = "CLEAN"
    scan_time_ms: float = 0.0