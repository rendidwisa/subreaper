# ── HTTP provider header prefixes ────────────────────────────────────────

PROVIDER_HEADER_PREFIXES = (
    "x-amz-",
    "x-azure-",
    "x-fastly-",
    "x-vercel-",
    "x-github-",
    "x-netlify-",
    "x-powered-by",
    "x-wp-",
    "cf-ray",
    "x-cdn",
    "x-zendesk-",
    "x-shopify-",
    "x-heroku-",
    "x-served-by",
)

# ── Default browser-like headers ─────────────────────────────────────────

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

# ── Bare error page patterns ─────────────────────────────────────────────

import re

BARE_ERROR_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"<title>\s*404\s*</title>",
        r"<title>\s*not found\s*</title>",
        r"<title>\s*error\s*</title>",
    )
)