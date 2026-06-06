from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IpPath:
    source:   str      
    via:      str
    ip:       str
    label:    str
    is_range: bool = False


@dataclass
class GhostIP:
    ip:            str
    via_subdomain: str
    source:        str        
    status:        str           
    http_status:   int   = 0
    body_preview:  str   = ""
    priority:      int   = 0
    has_admin_panel:  bool = False
    has_default_page: bool = False
    has_error_page:   bool = False


@dataclass
class GhostService:
    domain:         str
    cname_target:   str
    provider:       str
    http_status:    int
    severity:       int
    evidence:       list = field(default_factory=list)
    recommendation: str  = ""


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
    origin_ips: list = field(default_factory=list)
    asn_info: list = field(default_factory=list)
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
    origin_result: Optional[tuple] = None
    ghost_services: list = field(default_factory=list)