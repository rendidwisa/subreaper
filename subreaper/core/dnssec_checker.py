from __future__ import annotations

import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from subreaper.data.dnssec_signals import (
    DNSSEC_ALGORITHMS,
    WEAK_ALGORITHM_NUMBERS,
    NSEC_WALK_PROBE_PREFIX,
    ZONE_TRANSFER_RECORD_TYPES,
    WHOIS_AVAILABLE_SIGNALS,
    WHOIS_SERVERS,
)
from subreaper.models import DnssecResult, ZoneTransferResult, DanglingDelegationResult

_executor = ThreadPoolExecutor(max_workers=6)


class DnssecChecker:

    async def check_all(
        self,
        domain: str,
        subdomains_with_cname: list[tuple[str, str]],  
    ) -> tuple[
        list[DnssecResult],
        list[ZoneTransferResult],
        list[DanglingDelegationResult],
    ]:
        dnssec_task   = self._check_dnssec(domain)
        zone_task     = self._check_zone_transfer(domain)
        delegation_tasks = [
            self._check_dangling_delegation(sub, cname)
            for sub, cname in subdomains_with_cname
        ]

        dnssec_results, zone_results, *delegation_results = await asyncio.gather(
            dnssec_task, zone_task, *delegation_tasks, return_exceptions=True
        )

        def _safe_list(val, default=None):
            if isinstance(val, Exception) or val is None:
                return default or []
            if isinstance(val, list):
                return val
            return [val]

        return (
            _safe_list(dnssec_results),
            _safe_list(zone_results),
            [r for r in delegation_results if r and not isinstance(r, Exception)],
        )

    # ── DNSSEC Algorithm + NSEC Walking ──────────────────────────────────────

    async def _check_dnssec(self, domain: str) -> list[DnssecResult]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(_executor, self._check_dnssec_sync, domain)

    def _check_dnssec_sync(self, domain: str) -> list[DnssecResult]:
        results = []

        # 1. Ambil DNSKEY
        try:
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, dns.flags.DO, 4096)

            dnskey_answer = resolver.resolve(domain, "DNSKEY")
            has_dnssec = True

            for rdata in dnskey_answer:
                algo_num  = rdata.algorithm
                algo_info = DNSSEC_ALGORITHMS.get(algo_num, {
                    "name": f"UNKNOWN({algo_num})",
                    "status": "UNKNOWN",
                    "cve": None,
                })
                is_weak = algo_num in WEAK_ALGORITHM_NUMBERS

                severity = "HIGH" if is_weak else "INFO"
                rec = "Upgrade DNSSEC algorithm immediately." if is_weak else "Algorithm is acceptable."
                if algo_info.get("cve"):
                    rec += f" See {algo_info['cve']}."

                results.append(DnssecResult(
                    domain=domain,
                    has_dnssec=True,
                    algorithm_number=algo_num,
                    algorithm_name=algo_info["name"],
                    algorithm_status=algo_info["status"],
                    cve_reference=algo_info.get("cve"),
                    severity=severity,
                    recommendation=rec,
                ))

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Tidak ada DNSKEY — domain tidak pakai DNSSEC
            results.append(DnssecResult(
                domain=domain,
                has_dnssec=False,
                severity="INFO",
                recommendation="Domain does not use DNSSEC.",
            ))
            return results
        except Exception:
            return results

        # 2. NSEC Walking attempt
        nsec_result = self._attempt_nsec_walk(domain)
        if nsec_result:
            enumerated, nsec_type = nsec_result
            # Update result pertama dengan NSEC info
            if results:
                results[0].nsec_walkable   = True
                results[0].nsec_type       = nsec_type
                results[0].enumerated_names = enumerated
                results[0].severity        = "HIGH"
                results[0].recommendation  = (
                    f"NSEC zone walking enumerated {len(enumerated)} names. "
                    "Migrate to NSEC3 with opt-out to prevent subdomain enumeration."
                )

        # 3. Cek RRSIG
        try:
            resolver.resolve(domain, "RRSIG")
        except Exception:
            if results:
                results[0].rrsig_missing = True
                if results[0].severity == "INFO":
                    results[0].severity = "MEDIUM"
                results[0].recommendation += " RRSIG missing — DNSSEC validation may fail."

        return results

    def _attempt_nsec_walk(self, domain: str) -> tuple[list[str], str] | None:
        """
        Walk NSEC chain — query nama yang tidak ada, server return
        NSEC record yang menunjukkan range nama yang ada.
        Return (enumerated_names, nsec_type) atau None jika tidak walkable.
        """
        enumerated: list[str] = []
        try:
            qname = dns.name.from_text(f"{NSEC_WALK_PROBE_PREFIX}.{domain}.")
            request = dns.message.make_query(qname, dns.rdatatype.A, use_edns=True)
            request.flags |= dns.flags.DO  # DO bit — minta DNSSEC records

            nameservers = []
            try:
                ns_answers = dns.resolver.resolve(domain, "NS")
                for ns in ns_answers:
                    try:
                        a = dns.resolver.resolve(str(ns), "A")
                        nameservers.append(str(a[0]))
                    except Exception:
                        pass
            except Exception:
                return None

            if not nameservers:
                return None

            response = dns.query.udp(request, nameservers[0], timeout=5)

            # Cek apakah ada NSEC di authority section
            nsec_type = None
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NSEC:
                    nsec_type = "NSEC"
                    for rdata in rrset:
                        # Next name di NSEC record = nama berikutnya yang ada
                        next_name = str(rdata.next).rstrip(".")
                        if next_name and next_name != domain:
                            enumerated.append(next_name)
                elif rrset.rdtype == dns.rdatatype.NSEC3:
                    nsec_type = "NSEC3"
                    # NSEC3 hashed — tidak walkable dengan cara biasa
                    return None

            if nsec_type == "NSEC" and enumerated:
                # Walk lebih jauh — query nama setelah yang ditemukan
                enumerated = self._walk_nsec_chain(domain, nameservers[0], enumerated, max_steps=50)
                return enumerated, "NSEC"

        except Exception:
            pass

        return None

    def _walk_nsec_chain(
        self,
        domain: str,
        nameserver: str,
        initial: list[str],
        max_steps: int = 50,
    ) -> list[str]:
        found = set(initial)
        to_probe = list(initial)
        steps = 0

        while to_probe and steps < max_steps:
            probe = to_probe.pop(0)
            steps += 1
            try:
                qname   = dns.name.from_text(f"{probe}.")
                request = dns.message.make_query(qname, dns.rdatatype.A, use_edns=True)
                request.flags |= dns.flags.DO
                response = dns.query.udp(request, nameserver, timeout=3)

                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NSEC:
                        for rdata in rrset:
                            next_name = str(rdata.next).rstrip(".")
                            if (
                                next_name
                                and domain in next_name
                                and next_name not in found
                                and next_name != domain
                            ):
                                found.add(next_name)
                                to_probe.append(next_name)
            except Exception:
                continue

        return sorted(found)

    # ── Zone Transfer ─────────────────────────────────────────────────────────

    async def _check_zone_transfer(self, domain: str) -> list[ZoneTransferResult]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(_executor, self._zone_transfer_sync, domain)

    def _zone_transfer_sync(self, domain: str) -> list[ZoneTransferResult]:
        results = []

        try:
            ns_answers = dns.resolver.resolve(domain, "NS")
            nameservers = [str(ns).rstrip(".") for ns in ns_answers]
        except Exception:
            return results

        for ns_host in nameservers:
            try:
                ns_ips = socket.getaddrinfo(ns_host, 53, proto=socket.IPPROTO_TCP)
                ns_ip  = ns_ips[0][4][0]
            except Exception:
                continue

            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, timeout=10, lifetime=15)
                )

                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        rtype = dns.rdatatype.to_text(rdataset.rdtype)
                        if rtype not in ZONE_TRANSFER_RECORD_TYPES:
                            continue
                        for rdata in rdataset:
                            records.append({
                                "name":  str(name),
                                "type":  rtype,
                                "value": str(rdata),
                                "ttl":   rdataset.ttl,
                            })

                results.append(ZoneTransferResult(
                    domain=domain,
                    nameserver=ns_host,
                    success=True,
                    record_count=len(records),
                    records=records,
                    severity="CRITICAL",
                    recommendation=(
                        f"Disable AXFR on {ns_host}. "
                        "Restrict zone transfer to authorized secondary nameservers only "
                        "using ACL (e.g. 'allow-transfer { trusted_ip; };' in BIND)."
                    ),
                ))

            except (dns.exception.FormError, EOFError):
                # AXFR ditolak — bukan vuln
                continue
            except Exception:
                continue

        return results

    # ── Dangling CNAME Delegation ─────────────────────────────────────────────

    async def _check_dangling_delegation(
        self, subdomain: str, cname_target: str
    ) -> DanglingDelegationResult | None:
        # Ekstrak apex domain dari CNAME target
        parts = cname_target.rstrip(".").split(".")
        if len(parts) < 2:
            return None

        delegated_domain = ".".join(parts[-2:])

        # Skip jika cname target masih di bawah domain yang sama
        subdomain_apex = ".".join(subdomain.rstrip(".").split(".")[-2:])
        if delegated_domain == subdomain_apex:
            return None

        loop = asyncio.get_running_loop()
        status, whois_raw = await loop.run_in_executor(
            _executor, self._whois_check, delegated_domain
        )

        is_vulnerable = status == "available"
        severity      = "CRITICAL" if is_vulnerable else "INFO"
        rec           = ""
        if is_vulnerable:
            rec = (
                f"Domain '{delegated_domain}' appears available for registration. "
                f"An attacker can register it, set up authoritative NS, "
                f"and serve arbitrary content under '{subdomain}'. "
                "Remove or update the CNAME record immediately."
            )

        return DanglingDelegationResult(
            subdomain=subdomain,
            delegated_domain=delegated_domain,
            delegated_domain_status=status,
            is_vulnerable=is_vulnerable,
            whois_raw=whois_raw[:500] if whois_raw else None,
            severity=severity,
            recommendation=rec,
        )

    @staticmethod
    def _whois_check(domain: str) -> tuple[str, str | None]:
        """
        Cek availability domain via raw WHOIS socket.
        Return: ("available" | "registered" | "unknown", raw_response)
        """
        tld = "." + domain.split(".")[-1].lower()
        whois_server = WHOIS_SERVERS.get(tld, "whois.iana.org")

        try:
            with socket.create_connection((whois_server, 43), timeout=8) as sock:
                sock.sendall(f"{domain}\r\n".encode())
                raw = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk

            response = raw.decode(errors="replace").lower()

            for signal in WHOIS_AVAILABLE_SIGNALS:
                if signal in response:
                    return "available", response

            return "registered", response

        except Exception:
            return "unknown", None