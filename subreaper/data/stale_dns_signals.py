from __future__ import annotations

CLOUD_IP_RANGES: dict[str, list[str]] = {
    "AWS": [
        "52.0.0.0/8", "54.0.0.0/8", "3.0.0.0/8", "18.0.0.0/8",
        "34.192.0.0/10", "35.153.0.0/16",
    ],
    "GCP": [
        "34.0.0.0/8", "35.184.0.0/13", "104.154.0.0/15",
        "130.211.0.0/16", "146.148.0.0/17",
    ],
    "Azure": [
        "13.64.0.0/11", "13.96.0.0/13", "20.0.0.0/8",
        "40.64.0.0/10", "52.224.0.0/11",
    ],
    "DigitalOcean": [
        "104.131.0.0/16", "138.197.0.0/16", "159.65.0.0/16",
        "167.99.0.0/16", "174.138.0.0/16",
    ],
    "Linode": [
        "45.33.0.0/16", "45.56.0.0/16", "96.126.0.0/16",
        "173.255.0.0/16",
    ],
    "Vultr": [
        "45.32.0.0/16", "45.63.0.0/16", "104.207.0.0/16",
        "108.61.0.0/16",
    ],
}

TXT_VENDOR_PATTERNS: list[dict] = [
    {"vendor": "Google Workspace",  "pattern": "google-site-verification=",      "severity": "LOW"},
    {"vendor": "SendGrid",          "pattern": "v=spf1.*sendgrid",               "severity": "LOW"},
    {"vendor": "Mailgun",           "pattern": "v=spf1.*mailgun",                "severity": "LOW"},
    {"vendor": "Mailchimp",         "pattern": "v=spf1.*mcsv.net",              "severity": "LOW"},
    {"vendor": "HubSpot",          "pattern": "hs-site-verification=",          "severity": "LOW"},
    {"vendor": "Stripe",           "pattern": "stripe-verification=",           "severity": "MEDIUM"},
    {"vendor": "Braintree",        "pattern": "braintree-domain-verification=", "severity": "MEDIUM"},
    {"vendor": "Atlassian",        "pattern": "atlassian-domain-verification=", "severity": "LOW"},
    {"vendor": "Zoom",             "pattern": "zoom-domain-verification=",      "severity": "LOW"},
    {"vendor": "Adobe",            "pattern": "adobe-idp-site-verification=",   "severity": "LOW"},
    {"vendor": "Shopify",          "pattern": "shopify-domain-verification=",   "severity": "LOW"},
    {"vendor": "Facebook",         "pattern": "facebook-domain-verification=",  "severity": "LOW"},
    {"vendor": "Twilio SendGrid",  "pattern": "twilio-domain-verification=",    "severity": "LOW"},
    {"vendor": "Klaviyo",          "pattern": "klaviyo-site-verification=",     "severity": "LOW"},
    {"vendor": "Postmark",         "pattern": "pm-bounces",                     "severity": "LOW"},
]

MX_ZOMBIE_SEVERITY = "HIGH"
ZOMBIE_A_PTR_MISMATCH_SEVERITY = "MEDIUM"
ZOMBIE_A_NO_PTR_SEVERITY = "LOW"