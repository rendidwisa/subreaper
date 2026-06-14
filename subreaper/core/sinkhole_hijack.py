import asyncio
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
import urllib.request
import urllib.error
import ssl as ssl_mod
from subreaper.data.fingerprints import TAKEOVER_FINGERPRINTS

import dns.resolver
from subreaper.models import DNSInfo, SinkholeResult, SinkholeService, SinkholeHijackResult, ServiceSinkholeResult
from subreaper.data.sinkhole_signal import (
    SINKHOLE_PROBE_DOMAINS,
    SINKHOLE_PROBE_PORTS,
    SINKHOLE_DEFAULT_CREDENTIALS,
    SINKHOLE_LOGIN_ENDPOINTS,
    INTERNAL_IP_RANGES,
    PUBLIC_DNS_RESOLVERS,
    KNOWN_SINKHOLE_PUBLIC_IPS,
)
from subreaper.data.http_signals import DEFAULT_HEADERS

class SinkholeHijacker:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._internal_ranges = [self._parse_range(r) for r in INTERNAL_IP_RANGES]

    def _parse_range(self, cidr: str):
        import ipaddress
        return ipaddress.ip_network(cidr, strict=False)

    def _is_private_ip(self, ip_str: str) -> bool:
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_str)
            for rng in self._internal_ranges:
                if ip in rng:
                    return True
            return ip.is_private
        except ValueError:
            return False

    def _resolve_via(self, domain: str, resolver_ip: str) -> list[str]:
        try:
            r = dns.resolver.Resolver()
            r.nameservers = [resolver_ip]
            r.timeout = self.timeout
            r.lifetime = self.timeout
            answers = r.resolve(domain, "A")
            return [str(a) for a in answers]
        except Exception:
            return []

    def _probe_port(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(5, self.timeout))
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _grab_banner(self, ip: str, port: int, hostname: str = "") -> dict:
        try:
            if port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=min(5, self.timeout)) as sock:
                    with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                        cert = ssock.getpeercert()
                        cn = ""
                        if cert:
                            for sub in cert.get("subject", []):
                                for k, v in sub:
                                    if k == "commonName":
                                        cn = v
                        ssock.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % (hostname or ip).encode())
                        resp = ssock.recv(4096).decode("utf-8", errors="ignore")
                        server = ""
                        for line in resp.split("\r\n"):
                            if line.lower().startswith("server:"):
                                server = line.split(":", 1)[1].strip()
                        return {"service": "https", "banner": server, "ssl_cn": cn}
            elif port == 22:
                with socket.create_connection((ip, port), timeout=min(5, self.timeout)) as sock:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    return {"service": "ssh", "banner": banner, "ssl_cn": ""}
            else:
                with socket.create_connection((ip, port), timeout=min(5, self.timeout)) as sock:
                    sock.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % (hostname or ip).encode())
                    resp = sock.recv(4096).decode("utf-8", errors="ignore")
                    server = ""
                    for line in resp.split("\r\n"):
                        if line.lower().startswith("server:"):
                            server = line.split(":", 1)[1].strip()
                    return {"service": "http", "banner": server, "ssl_cn": ""}
        except Exception as e:
            return {"service": "unknown", "banner": "", "ssl_cn": "", "error": str(e)}

    def _try_login(self, ip: str, port: int) -> Optional[dict]:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import base64
        import ssl as ssl_mod
        import urllib.request

        def attempt(cred, endpoint):
            try:
                auth_str = f"{cred['username']}:{cred['password']}"
                b64 = base64.b64encode(auth_str.encode()).decode()
                protocol = "https" if port in (443, 8443) else "http"
                url = f"{protocol}://{ip}:{port}{endpoint}"
                req = urllib.request.Request(url)
                for key, value in DEFAULT_HEADERS.items():
                    if key.lower() != "accept-encoding":
                        req.add_header(key, value)
                req.add_header("Accept-Encoding", "gzip, deflate")
                req.add_header("Authorization", f"Basic {b64}")
                ctx = None
                if protocol == "https":
                    ctx = ssl_mod.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl_mod.CERT_NONE
                with urllib.request.urlopen(req, timeout=min(2, self.timeout), context=ctx) as resp:
                    if resp.status == 200:
                        body = resp.read(512).decode("utf-8", errors="ignore").lower()
                        indicators = ["dashboard", "admin", "welcome", "panel", "logout", "token"]
                        if any(ind in body for ind in indicators):
                            return (cred, endpoint)
            except Exception:
                pass
            return None

        tasks = []
        with ThreadPoolExecutor(max_workers=15) as executor:
            for cred in SINKHOLE_DEFAULT_CREDENTIALS:
                for endpoint in SINKHOLE_LOGIN_ENDPOINTS:
                    tasks.append(executor.submit(attempt, cred, endpoint))
            
            for future in as_completed(tasks):
                result = future.result(timeout=2)
                if result:
                    cred, endpoint = result
                    return {"username": cred["username"], "password": cred["password"], "endpoint": endpoint}
        return None

    def detect_sinkhole(self, domain: str, resolver_ip: Optional[str] = None) -> SinkholeResult:
        if resolver_ip is None:
            resolver_ip = PUBLIC_DNS_RESOLVERS[0]
        evidence = []
        internal_ips = []
        sinkhole_detected = False
        sinkhole_ip = None
        target_ips = self._resolve_via(domain, resolver_ip)

        for probe_domain in SINKHOLE_PROBE_DOMAINS:
            ips = self._resolve_via(probe_domain, resolver_ip)
            if ips and (self._is_private_ip(ips[0]) or ips[0] in KNOWN_SINKHOLE_PUBLIC_IPS):
                sinkhole_detected = True
                sinkhole_ip = ips[0]
                evidence.append(f"{probe_domain} -> {ips[0]} (private IP via {resolver_ip})")
                if ips[0] not in internal_ips:
                    internal_ips.append(ips[0])

        severity = "CRITICAL" if sinkhole_detected else "INFO"
        return SinkholeResult(
            domain=domain,
            sinkhole_detected=sinkhole_detected,
            sinkhole_ip=sinkhole_ip,
            resolver_used=resolver_ip,
            internal_ips_exposed=internal_ips,
            evidence=evidence,
            severity=severity,
        )

    def detect_service_sinkhole(self, domain: str, dns_info) -> ServiceSinkholeResult:
        if not dns_info or not dns_info.a_records:
            return ServiceSinkholeResult(detected=False)
        
        cname_targets = []
        if dns_info.cname_chain:
            cname_targets = [hop.get("to", "").lower() for hop in dns_info.cname_chain]
        
        candidate_entries = []
        for entry in TAKEOVER_FINGERPRINTS:
            patterns = entry.get("cname_patterns", [])
            if any(any(p in target for p in patterns) for target in cname_targets):
                candidate_entries.append(entry)
        if not candidate_entries:
            candidate_entries = [
                e for e in TAKEOVER_FINGERPRINTS
                if e.get("confidence") in ("HIGH",) and e.get("risk_weight", 0) >= 70
            ]

        for protocol in ("https", "http"):
            try:
                url = f"{protocol}://{domain}"
                req = urllib.request.Request(url)
                req.add_header("Host", domain)
                ctx = None
                if protocol == "https":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                
                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    body = resp.read(16384).decode("utf-8", errors="ignore").lower()
                    status = resp.status
            except urllib.error.HTTPError as e:
                body = e.read(16384).decode("utf-8", errors="ignore").lower()
                status = e.code
            except Exception:
                continue

            for entry in candidate_entries:
                expected_codes = entry.get("http_codes", [])
                fingerprints = entry.get("response_fingerprints", [])
                
                if expected_codes and status not in expected_codes:
                    continue
                
                matched = []
                for fp in fingerprints:
                    if fp["pattern"].lower() in body:
                        matched.append(fp)
                
                if matched:
                    strongest = max(matched, key=lambda x: (
                        {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["strength"], 0)
                    ))
                    return ServiceSinkholeResult(
                        detected=True,
                        provider=entry["service"],
                        status=status,
                        claimable=entry.get("claimable", False),
                        confidence=entry.get("confidence", "MEDIUM"),
                        evidence=[
                            f"Provider: {entry['service']}",
                            f"HTTP {status}",
                            f"Pattern: {strongest['pattern'][:80]}",
                            f"Strength: {strongest['strength']}",
                            f"Claimable: {entry.get('claimable', False)}",
                        ]
                    )
        return ServiceSinkholeResult(detected=False)
        
    def probe_services(self, sinkhole_ip: str, aggressive: bool = False, domain: str = "") -> list[SinkholeService]:
        ports = SINKHOLE_PROBE_PORTS if aggressive else [80, 443, 8080, 8443]
        results = []
        for port in ports:
            open_port = self._probe_port(sinkhole_ip, port)
            svc = SinkholeService(port=port, open=open_port)
            if open_port:
                info = self._grab_banner(sinkhole_ip, port, hostname=domain)
                svc.service = info.get("service", "")
                svc.banner = info.get("banner", "")
                svc.ssl_cn = info.get("ssl_cn", "")
            results.append(svc)
        return results

    def try_hijack(self, sinkhole_ip: str, services: list[SinkholeService]) -> SinkholeHijackResult:
        evidence = []
        hijacked = []
        available = []

        for svc in services:
            if not svc.open:
                continue
            if svc.port in (80, 443, 8080, 8443):
                available.append(svc)
                login_result = self._try_login(sinkhole_ip, svc.port)
                if login_result:
                    svc.default_creds = login_result
                    svc.login_endpoint = login_result["endpoint"]
                    svc.is_hijackable = True
                    hijacked.append(svc)
                    evidence.append(f"Default login berhasil di port {svc.port}: {login_result['username']}:{login_result['password']} via {login_result['endpoint']}")

        hijackable = len(hijacked) > 0
        severity = "CRITICAL" if hijackable else "MEDIUM"
        rec = ""
        if hijackable:
            rec = f"Sinkhole di {sinkhole_ip} bisa di-hijack via {len(hijacked)} service dengan default credentials. Segera ganti credential dan isolasi IP sinkhole."
        elif available:
            rec = f"Service internal terdeteksi di {sinkhole_ip} tapi tidak dengan default credentials. Coba brute force atau cari credentials bocor."
        else:
            rec = f"Sinkhole terdeteksi di {sinkhole_ip} tapi tidak ada service HTTP yang bisa diakses."

        return SinkholeHijackResult(
            domain=sinkhole_ip,
            sinkhole_ip=sinkhole_ip,
            hijackable=hijackable,
            hijacked_services=hijacked,
            available_services=available,
            evidence=evidence,
            severity=severity,
            recommendation=rec,
        )

    def find_alternative_resolver(self, domain: str) -> list[dict]:
        results = []
        seen_ips = set()
        for resolver in PUBLIC_DNS_RESOLVERS:
            ips = self._resolve_via(domain, resolver)
            if ips:
                ip = ips[0]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    is_private = self._is_private_ip(ip)
                    results.append({
                        "resolver": resolver,
                        "ip": ip,
                        "is_private": is_private,
                    })
        return results

    def analyze(self, domain: str, dns_info: Optional[DNSInfo] = None, aggressive: bool = False) -> dict:
        resolver_ip = PUBLIC_DNS_RESOLVERS[0]
        if dns_info and dns_info.ns_records:
            try:
                ns = dns_info.ns_records[0]
                ns_ips = self._resolve_via(ns, PUBLIC_DNS_RESOLVERS[0])
                if ns_ips:
                    test = self._resolve_via("google.com", ns_ips[0])
                    if test:
                        resolver_ip = ns_ips[0]
            except Exception:
                pass

        sinkhole_result = self.detect_sinkhole(domain, resolver_ip)
        service_sinkhole_result = self.detect_service_sinkhole(domain, dns_info)

        services = []
        hijack_result = None
        alt_resolvers = []

        if sinkhole_result.sinkhole_detected and sinkhole_result.sinkhole_ip:
            actual_ips = self._resolve_via(domain, resolver_ip)
            target_ip = actual_ips[0] if actual_ips else sinkhole_result.sinkhole_ip
            services = self.probe_services(target_ip, aggressive)
            hijack_result = self.try_hijack(target_ip, services)
        elif service_sinkhole_result.detected and aggressive:
            target_ips = dns_info.a_records[:3]  
            for ip in target_ips:
                svcs = self.probe_services(ip, aggressive)
                if any(svc.open for svc in svcs if svc.port in (80,443,8080,8443)):
                    hijack_result = self.try_hijack(ip, svcs)
                    services.extend(svcs)
                    break
                services.extend(svcs)
        alt_resolvers = self.find_alternative_resolver(domain)

        return {
            "sinkhole": sinkhole_result,
            "service_sinkhole": service_sinkhole_result,
            "services": services,
            "hijack": hijack_result,
            "alternative_resolvers": alt_resolvers,
        }

    def analyze_batch(self, domains: list[str], dns_info_map: dict[str, DNSInfo], aggressive: bool = False) -> dict[str, dict]:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for d in domains:
                info = dns_info_map.get(d)
                futures[executor.submit(self.analyze, d, info, aggressive)] = d
            results = {}
            for f in futures:
                d = futures[f]
                try:
                    results[d] = f.result()
                except Exception as e:
                    results[d] = {"error": str(e)}
            return results