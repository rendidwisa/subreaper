from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime, timezone

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
    dmarc_record: Optional[str] = None
    dkim_records: list[str] = field(default_factory=list)
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
    severity: str = "INFO"
    description: str = ""
    fix: str = ""

    risk_score: int = 0
    exploitability: str = "NONE"
    verification_stage: str = "DNS"
    provider: str = ""
    is_claimable: bool = False
    evidence_level: str = "WEAK"

@dataclass
class StaleDnsResult:
    domain:       str
    scenario:     str
    record_type:  str
    record_value: str
    reason:       str
    severity:     str
    recommendation: str
    mx_priority:  Optional[int]  = None
    ip_owner_info:   Optional[str]  = None
    ip_is_cloud:     Optional[bool] = None
    ip_reverse_dns:  Optional[str]  = None
    vendor_name:         Optional[str] = None
    txt_matched_pattern: Optional[str] = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id:     Optional[str]      = None
    first_seen:  Optional[datetime] = None
    raw_dns_response: Optional[str] = None

@dataclass
class CorsChainResult:
    affected_domain:   str
    dangerous_origin:  str
    cors_value:        str
    credentials:       bool
    vuln_type:         str
    severity:          str
    recommendation:    str
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class DnssecResult:
    domain:           str
    has_dnssec:       bool
    algorithm_number: Optional[int]       = None
    algorithm_name:   Optional[str]       = None
    algorithm_status: Optional[str]       = None   
    cve_reference:    Optional[str]       = None
    nsec_walkable:    bool                = False
    nsec_type:        Optional[str]       = None  
    enumerated_names: list[str]           = field(default_factory=list)
    rrsig_missing:    bool                = False
    severity:         str                 = "INFO"
    recommendation:   str                 = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class ZoneTransferResult:
    domain:        str
    nameserver:    str
    success:       bool
    record_count:  int                    = 0
    records:       list[dict]             = field(default_factory=list)
    severity:      str                    = "CRITICAL"
    recommendation: str                   = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class DanglingDelegationResult:
    subdomain:              str
    delegated_domain:       str
    delegated_domain_status: str          
    is_vulnerable:          bool
    whois_raw:              Optional[str] = None
    registrar_hint:         Optional[str] = None
    severity:               str           = "CRITICAL"
    recommendation:         str           = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class SinkholeResult:
    domain: str
    sinkhole_detected: bool
    sinkhole_ip: Optional[str] = None
    resolver_used: str = ""
    internal_ips_exposed: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    severity: str = "INFO"
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SinkholeService:
    port: int
    open: bool
    service: str = ""
    banner: str = ""
    ssl_cn: str = ""
    default_creds: Optional[dict] = None
    login_endpoint: str = ""
    is_hijackable: bool = False


@dataclass
class SinkholeHijackResult:
    domain: str
    sinkhole_ip: str
    hijackable: bool
    hijacked_services: list[SinkholeService] = field(default_factory=list)
    available_services: list[SinkholeService] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    severity: str = "CRITICAL"
    recommendation: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class ServiceSinkholeResult:
    detected: bool
    provider: Optional[str] = None
    status: Optional[int] = None
    claimable: bool = False
    confidence: str = "LOW"
    evidence: list[str] = field(default_factory=list)

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
    stale_dns_results: list = field(default_factory=list)
    cors_chain_results: list = field(default_factory=list)
    dnssec_results:           list = field(default_factory=list)
    zone_transfer_results:    list = field(default_factory=list)
    dangling_delegation_results: list = field(default_factory=list)
    sinkhole_results: Optional[SinkholeResult] = None
    sinkhole_hijack_results: Optional[SinkholeHijackResult] = None
    service_sinkhole_results: Optional[ServiceSinkholeResult] = None