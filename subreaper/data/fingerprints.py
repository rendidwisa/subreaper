"""
Fingerprint database for subdomain takeover detection.

Each entry defines:
  - service          : Name of the cloud/SaaS service
  - cname_patterns   : Substrings to match against CNAME targets
  - response_fingerprints : Strings that appear in HTTP body when resource is unclaimed
  - http_codes       : Expected HTTP status codes for a vulnerable response
  - confidence       : HIGH | MEDIUM
  - references       : Public reference for the takeover technique

To add a new service, append a new dict to TAKEOVER_FINGERPRINTS following
the same schema. No other files need to be changed.
"""

TAKEOVER_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "github.com"],
        "response_fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://github.com/EdOverflow/can-i-take-over-xyz",
    },
    {
        "service": "Heroku",
        "cname_patterns": ["herokudns.com", "herokuapp.com", "herokussl.com"],
        "response_fingerprints": [
            "No such app",
            "There is no app configured at that hostname",
            "herokucdn.com/error-pages/no-such-app.html",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://devcenter.heroku.com",
    },
    {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com", "shopify.com"],
        "response_fingerprints": [
            "Sorry, this shop is currently unavailable.",
            "Only one step left!",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://can-i-take-over-xyz.github.io",
    },
    {
        "service": "Fastly",
        "cname_patterns": ["fastly.net"],
        "response_fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://developer.fastly.com",
    },
    {
        "service": "AWS S3",
        "cname_patterns": ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
        "response_fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "The bucket you are attempting to access must be addressed using the specified endpoint",
        ],
        "http_codes": [404, 403],
        "confidence": "HIGH",
        "references": "https://aws.amazon.com/s3/",
    },
    {
        "service": "Azure",
        "cname_patterns": [
            "azurewebsites.net",
            "cloudapp.net",
            "cloudapp.azure.com",
            "trafficmanager.net",
            "blob.core.windows.net",
            "azure-api.net",
            "azurehdinsight.net",
            "azureedge.net",
        ],
        "response_fingerprints": [
            "404 Web Site not found",
            "Error 404 - Web app not found",
            "The resource you are looking for has been removed",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://docs.microsoft.com/azure",
    },
    {
        "service": "Netlify",
        "cname_patterns": ["netlify.com", "netlify.app"],
        "response_fingerprints": [
            "Not Found - Request ID",
            "No site with that URL",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://netlify.com",
    },
    {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "now.sh"],
        "response_fingerprints": [
            "The deployment you are trying to access does not exist",
            "This deployment has been disabled",
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "references": "https://vercel.com",
    },
    {
        "service": "WP Engine",
        "cname_patterns": ["wpengine.com"],
        "response_fingerprints": [
            "The site you were looking for couldn't be found",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://wpengine.com",
    },
    {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "response_fingerprints": [
            "Help Center Closed",
            "Page not found",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://zendesk.com",
    },
    {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io", "getpantheon.com"],
        "response_fingerprints": [
            "The gods are wise, but do not know of the site which you seek",
            "404 error unknown site!",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://pantheon.io",
    },
    {
        "service": "Tumblr",
        "cname_patterns": ["tumblr.com"],
        "response_fingerprints": [
            "Whatever you were looking for doesn't currently exist at this address",
            "There's nothing here.",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://tumblr.com",
    },
    {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "response_fingerprints": [
            "project not found",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://surge.sh",
    },
    {
        "service": "Squarespace",
        "cname_patterns": ["squarespace.com"],
        "response_fingerprints": [
            "No Such Account",
        ],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "references": "https://squarespace.com",
    },
    {
        "service": "HubSpot",
        "cname_patterns": ["hubspot.com", "hs-sites.com"],
        "response_fingerprints": [
            "Domain Not Found",
            "This page isn't available",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://hubspot.com",
    },
    {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "response_fingerprints": [
            "Failed to resolve DNS for this domain",
            "Site does not exist",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://ghost.org",
    },
    {
        "service": "Render",
        "cname_patterns": ["onrender.com"],
        "response_fingerprints": [
            "Site Not Found",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://render.com",
    },
    {
        "service": "ReadTheDocs",
        "cname_patterns": ["readthedocs.io", "readthedocs.org"],
        "response_fingerprints": [
            "Unknown Host",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://readthedocs.org",
    },
    {
        "service": "Intercom",
        "cname_patterns": ["intercom.io", "intercom.com"],
        "response_fingerprints": [
            "This page is reserved for artistic dogs",
            "Uh oh. That page doesn't exist.",
        ],
        "http_codes": [404],
        "confidence": "HIGH",
        "references": "https://intercom.com",
    },
    {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev", "fly.io"],
        "response_fingerprints": ["Fly.io"],
        "http_codes": [404],
        "confidence": "MEDIUM",
        "references": "https://fly.io",
    },
]