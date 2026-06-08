# ── Ghost service detection signals ───────────────────────────────────────

SSO_SIGNALS = [
    "okta.com", "login.microsoftonline.com", "accounts.google.com",
    "auth0.com", "onelogin.com", "ping identity",
]

FOR_SALE_SIGNALS = [
    "buy", "domain for sale", "purchase this domain", "make an offer",
]

PROBE_HEADERS = {
    "Cache-Control": "no-cache",
    "Pragma":        "no-cache",
}

TLD_BRAND_HINTS: dict[str, str] = {
    "it": "italia", "de": "deutschland", "fr": "france",
    "es": "españa",  "br": "brasil",      "jp": "japan",
    "cn": "china",   "au": "australia",   "nl": "nederland",
}