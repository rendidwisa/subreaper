
import re

DKIM_COMMON_SELECTORS = [
    "default", "google", "selector1", "selector2",
    "k1", "mail", "email", "dkim", "smtp",
    "mandrill", "sendgrid", "mailchimp", "amazonses",
    "protonmail", "zoho", "mailjet", "postmark", "sparkpost",
]

# key: mechanism string  →  (severity, description)  |  None severity = secure
SPF_ALL_MECHANISMS = {
    "+all": ("CRITICAL", "Anyone can send as this domain (explicit pass-all)"),
    "?all": ("MEDIUM",   "Neutral policy — no enforcement"),
    "~all": ("LOW",      "Softfail — spoofing not blocked, only marked"),
    "-all": (None,      "Strict reject — secure"),
}

SPF_INCLUDE_LIMIT = 10

DMARC_POLICIES = {
    "none":       ("HIGH", "Monitor only — no email protection enforced"),
    "quarantine": ("LOW",  "Suspicious email routed to spam"),
    "reject":     (None,   "Strict rejection — secure"),
}

RE_SPF_VERSION  = re.compile(r"^v=spf1",         re.IGNORECASE)
RE_SPF_ALL      = re.compile(r"([+\-~?]all)\s*$", re.IGNORECASE)
RE_SPF_INCLUDE  = re.compile(r"\binclude:",       re.IGNORECASE)
RE_DMARC_VERSION = re.compile(r"^v=DMARC1",       re.IGNORECASE)
RE_DMARC_POLICY = re.compile(r"p=(\w+)",          re.IGNORECASE)
RE_DMARC_PCT    = re.compile(r"pct=(\d+)",        re.IGNORECASE)
RE_DKIM_VERSION = re.compile(r"v=DKIM1",          re.IGNORECASE)