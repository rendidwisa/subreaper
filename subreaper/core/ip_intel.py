"""
IP Intelligence — ASN, GeoIP via MaxMind GeoLite2 (primary) or DNS Cymru (fallback).
"""

from __future__ import annotations

import re
import os
from typing import Optional

import dns.resolver

try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

_DB_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
_ASN_DB_PATH = os.path.join(_DB_DIR, "GeoLite2-ASN.mmdb")
_CITY_DB_PATH = os.path.join(_DB_DIR, "GeoLite2-City.mmdb")

_asn_reader = None
_city_reader = None


def _init_readers():
    global _asn_reader, _city_reader
    if GEOIP2_AVAILABLE and _asn_reader is None:
        if os.path.exists(_ASN_DB_PATH):
            _asn_reader = geoip2.database.Reader(_ASN_DB_PATH)
        if os.path.exists(_CITY_DB_PATH):
            _city_reader = geoip2.database.Reader(_CITY_DB_PATH)


def _reverse_ip(ip: str) -> str:
    parts = ip.strip().split(".")
    return ".".join(reversed(parts))


def _lookup_geoip2(ip: str) -> Optional[dict]:
    """Gunakan MaxMind GeoIP2 untuk data lengkap."""
    _init_readers()
    result = {
        "asn": None,
        "asn_org": None,
        "country": None,
        "city": None,
        "latitude": None,
        "longitude": None,
        "prefix": None,
        "registry": None,
    }

    try:
        if _asn_reader:
            asn_resp = _asn_reader.asn(ip)
            result["asn"] = asn_resp.autonomous_system_number
            result["asn_org"] = asn_resp.autonomous_system_organization
            result["prefix"] = str(asn_resp.network) if asn_resp.network else None
    except Exception:
        pass

    try:
        if _city_reader:
            city_resp = _city_reader.city(ip)
            result["country"] = city_resp.country.iso_code
            result["city"] = city_resp.city.name
            result["latitude"] = city_resp.location.latitude
            result["longitude"] = city_resp.location.longitude
    except Exception:
        pass

    if result["asn"] is not None or result["country"] is not None:
        return result
    return None


def _lookup_dns(ip: str) -> Optional[dict]:
    """Fallback ke DNS Cymru (hanya ASN, negara, prefix, registry)."""
    reversed_ip = _reverse_ip(ip)
    try:
        query = f"AS{reversed_ip}.origin.asn.cymru.com"
        answers = dns.resolver.resolve(query, "TXT")
        text = answers[0].to_text().strip('"').strip("'")
        match = re.match(r"(\d+)\s*\|\s*([\d\.\/]+)\s*\|\s*(\w+)\s*\|\s*(\w+)\s*\|", text)
        if not match:
            return None

        asn = int(match.group(1))
        result = {
            "asn": asn,
            "asn_org": None,
            "country": match.group(3).strip(),
            "city": None,
            "latitude": None,
            "longitude": None,
            "prefix": match.group(2).strip(),
            "registry": match.group(4).strip(),
        }

        try:
            org_query = f"{asn}.asn.cymru.com"
            org_answers = dns.resolver.resolve(org_query, "TXT")
            org_text = org_answers[0].to_text().strip('"').strip("'")
            org_match = re.match(rf"{asn}\s*\|\s*(.+)", org_text)
            if org_match:
                result["asn_org"] = org_match.group(1).strip()
        except Exception:
            pass

        return result
    except Exception:
        return None


def lookup(ip: str) -> Optional[dict]:
    """
    Lookup ASN & GeoIP for IP.
    Priority: GeoIP2 (if available), fallback to DNS.
    """
    _init_readers()

    if GEOIP2_AVAILABLE and (_asn_reader or _city_reader):
        result = _lookup_geoip2(ip)
        if result:
            return result
    # Fallback
    return _lookup_dns(ip)