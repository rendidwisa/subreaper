PROVIDER_TYPE_SAAS = "SaaS"
PROVIDER_TYPE_CDN = "CDN"
PROVIDER_TYPE_CLOUD = "Cloud"

STRENGTH_STRONG = "HIGH"
STRENGTH_MEDIUM = "MEDIUM"
STRENGTH_WEAK   = "LOW"

SIGNAL_ORPHAN    = "orphan"
SIGNAL_ERROR     = "error"
SIGNAL_AMBIGUOUS = "ambiguous"

def _fp(pattern, strength=STRENGTH_STRONG, signal=SIGNAL_ORPHAN):
    return {"pattern": pattern, "strength": strength, "signal": signal}


TAKEOVER_FINGERPRINTS = [
    # ── AWS ──────────────────────────────────────────────────────────────
    {
        "service": "AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website"],
        "response_fingerprints": [
            _fp("NoSuchBucket"),
            _fp("The specified bucket does not exist"),
            _fp(
                "The bucket you are attempting to access must be addressed using the specified endpoint",
                STRENGTH_MEDIUM,
                SIGNAL_ERROR,
            ),
        ],
        "http_codes": [404, 403],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_CLOUD,
        "provider_group": "AWS",
        "risk_weight": 90,
        "references": "https://aws.amazon.com/s3/",
    },
    {
        "service": "AWS ELB",
        "cname_patterns": ["elb.amazonaws.com"],
        "response_fingerprints": [
            _fp("503 Service Temporarily Unavailable", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
        ],
        "http_codes": [503],
        "confidence": "MEDIUM",
        "claimable": False,
        "provider_type": PROVIDER_TYPE_CLOUD,
        "provider_group": "AWS",
        "risk_weight": 20,
        "references": "https://aws.amazon.com/elasticloadbalancing/",
    },
    {
        "service": "AWS CloudFront",
        "cname_patterns": ["cloudfront.net"],
        "response_fingerprints": [
            _fp("The request could not be satisfied", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
            _fp("Bad request", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
        ],
        "http_codes": [403, 400],
        "confidence": "MEDIUM",
        "claimable": False,
        "provider_type": PROVIDER_TYPE_CDN,
        "provider_group": "AWS",
        "risk_weight": 30,
        "references": "https://aws.amazon.com/cloudfront/",
    },
    # ── Azure ────────────────────────────────────────────────────────────
    {
        "service": "Azure App Service",
        "cname_patterns": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com"],
        "response_fingerprints": [
            _fp("Error 404 - Web app not found"),
            _fp(
                "The resource you are looking for has been removed",
                STRENGTH_MEDIUM,
                SIGNAL_ERROR,
            ),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_CLOUD,
        "provider_group": "Azure",
        "risk_weight": 80,
        "references": "https://docs.microsoft.com/azure/app-service",
    },
    {
        "service": "Azure Traffic Manager",
        "cname_patterns": ["trafficmanager.net"],
        "response_fingerprints": [
            _fp("404 Web Site not found", STRENGTH_MEDIUM),
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_CLOUD,
        "provider_group": "Azure",
        "risk_weight": 70,
        "references": "https://docs.microsoft.com/azure/traffic-manager",
    },
    {
        "service": "Azure CDN",
        "cname_patterns": ["azureedge.net"],
        "response_fingerprints": [
            _fp("404 Web Site not found", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "claimable": False,
        "provider_type": PROVIDER_TYPE_CDN,
        "provider_group": "Azure",
        "risk_weight": 30,
        "references": "https://docs.microsoft.com/azure/cdn",
    },
    {
        "service": "Azure Blob Storage",
        "cname_patterns": ["blob.core.windows.net"],
        "response_fingerprints": [
            _fp("BlobNotFound", STRENGTH_MEDIUM, SIGNAL_ERROR),
            _fp("The specified resource does not exist", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_CLOUD,
        "provider_group": "Azure",
        "risk_weight": 70,
        "references": "https://docs.microsoft.com/azure/storage/blobs",
    },
    {
        "service": "Azure API Management",
        "cname_patterns": ["azure-api.net"],
        "response_fingerprints": [
            _fp("Resource not found", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "claimable": False,
        "provider_type": PROVIDER_TYPE_CLOUD,
        "provider_group": "Azure",
        "risk_weight": 30,
        "references": "https://docs.microsoft.com/azure/api-management",
    },
    {
        "service": "Azure HDInsight",
        "cname_patterns": ["azurehdinsight.net"],
        "response_fingerprints": [
            _fp("404 Web Site not found", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "claimable": False,
        "provider_type": PROVIDER_TYPE_CLOUD,
        "provider_group": "Azure",
        "risk_weight": 25,
        "references": "https://docs.microsoft.com/azure/hdinsight",
    },
    # ── CDN ──────────────────────────────────────────────────────────────
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "response_fingerprints": [
            _fp("Fastly error: unknown domain"),
            _fp("Please check that this domain has been added to a service"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_CDN,
        "provider_group": "Fastly",
        "risk_weight": 85,
        "references": "https://developer.fastly.com",
    },
    # ── SaaS ─────────────────────────────────────────────────────────────
    {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "response_fingerprints": [
            _fp("Failed to resolve DNS for this domain"),
            _fp("Site does not exist"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Ghost",
        "risk_weight": 80,
        "references": "https://ghost.org",
    },
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io"],
        "response_fingerprints": [
            _fp("There isn't a GitHub Pages site here."),
            _fp(
                "For root URLs (like http://example.com/) you must provide an index.html file",
                STRENGTH_MEDIUM,
            ),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "GitHub",
        "risk_weight": 90,
        "references": "https://github.com/EdOverflow/can-i-take-over-xyz",
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokudns.com", "herokuapp.com", "herokussl.com"],
        "response_fingerprints": [
            _fp("No such app"),
            _fp("There is no app configured at that hostname"),
            _fp("herokucdn.com/error-pages/no-such-app.html"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Heroku",
        "risk_weight": 90,
        "references": "https://devcenter.heroku.com",
    },
    {
        "service": "HubSpot",
        "cname_patterns": ["hubspot.com", "hs-sites.com"],
        "response_fingerprints": [
            _fp("Domain Not Found"),
            _fp("This page isn't available", STRENGTH_MEDIUM, SIGNAL_ERROR),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "HubSpot",
        "risk_weight": 75,
        "references": "https://hubspot.com",
    },
    {
        "service": "Intercom",
        "cname_patterns": ["intercom.io", "intercom.com"],
        "response_fingerprints": [
            _fp("This page is reserved for artistic dogs"),
            _fp("Uh oh. That page doesn't exist.", STRENGTH_MEDIUM),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Intercom",
        "risk_weight": 75,
        "references": "https://intercom.com",
    },
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.com", "netlify.app"],
        "response_fingerprints": [
            _fp("Not Found - Request ID"),
            _fp("No site with that URL"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Netlify",
        "risk_weight": 85,
        "references": "https://netlify.com",
    },
    {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io", "getpantheon.com"],
        "response_fingerprints": [
            _fp("The gods are wise, but do not know of the site which you seek"),
            _fp("404 error unknown site!"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Pantheon",
        "risk_weight": 80,
        "references": "https://pantheon.io",
    },
    {
        "service": "ReadTheDocs",
        "cname_patterns": ["readthedocs.io", "readthedocs.org"],
        "response_fingerprints": [
            _fp("Unknown Host"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "ReadTheDocs",
        "risk_weight": 75,
        "references": "https://readthedocs.org",
    },
    {
        "service": "Render",
        "cname_patterns": ["onrender.com"],
        "response_fingerprints": [
            _fp("Site Not Found"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Render",
        "risk_weight": 80,
        "references": "https://render.com",
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com"],
        "response_fingerprints": [
            _fp("Sorry, this shop is currently unavailable."),
            _fp("Only one step left!", STRENGTH_MEDIUM),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Shopify",
        "risk_weight": 80,
        "references": "https://can-i-take-over-xyz.github.io",
    },
    {
        "service": "Squarespace",
        "cname_patterns": ["squarespace.com"],
        "response_fingerprints": [
            _fp("No Such Account"),
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "claimable": False,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Squarespace",
        "risk_weight": 40,
        "references": "https://squarespace.com",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "response_fingerprints": [
            _fp("project not found"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Surge",
        "risk_weight": 80,
        "references": "https://surge.sh",
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["tumblr.com"],
        "response_fingerprints": [
            _fp("Whatever you were looking for doesn't currently exist at this address"),
            _fp("There's nothing here.", STRENGTH_MEDIUM),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Tumblr",
        "risk_weight": 80,
        "references": "https://tumblr.com",
    },
    {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "now.sh"],
        "response_fingerprints": [
            _fp("The deployment you are trying to access does not exist"),
            _fp("This deployment has been disabled", STRENGTH_MEDIUM),
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "claimable": False,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Vercel",
        "risk_weight": 40,
        "references": "https://vercel.com",
    },
    {
        "service": "WP Engine",
        "cname_patterns": ["wpengine.com"],
        "response_fingerprints": [
            _fp("The site you were looking for couldn't be found"),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "WP Engine",
        "risk_weight": 75,
        "references": "https://wpengine.com",
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "response_fingerprints": [
            _fp("Help Center Closed"),
            _fp("Page not found", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "claimable": True,
        "provider_type": PROVIDER_TYPE_SAAS,
        "provider_group": "Zendesk",
        "risk_weight": 75,
        "references": "https://zendesk.com",
    },
    # ── Cloud (Other) ────────────────────────────────────────────────────
    {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev", "fly.io"],
        "response_fingerprints": [
            _fp("Fly.io", STRENGTH_WEAK, SIGNAL_AMBIGUOUS),
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "claimable": False,
        "provider_type": PROVIDER_TYPE_CLOUD,
        "provider_group": "Fly",
        "risk_weight": 35,
        "references": "https://fly.io",
    },
]


FINGERPRINT_BY_SERVICE = {entry["service"]: entry for entry in TAKEOVER_FINGERPRINTS}

PROVIDER_GROUPS = {}
for _entry in TAKEOVER_FINGERPRINTS:
    _group = _entry["provider_group"]
    if _group not in PROVIDER_GROUPS:
        PROVIDER_GROUPS[_group] = []
    PROVIDER_GROUPS[_group].append(_entry["service"])


STRENGTH_SCORE = {
    "HIGH":   40,
    "MEDIUM": 25,
    "LOW":    10,
}

CONFIDENCE_SCORE = {
    "HIGH":   90,
    "MEDIUM": 60,
    "LOW":    30,
}