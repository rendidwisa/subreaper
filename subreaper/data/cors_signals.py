from __future__ import annotations

CORS_HEADERS: tuple[str, ...] = (
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
)

CORS_PROBE_VALID_STATUS: set[int] = {200, 301, 302, 403}

CORS_WILDCARD_VALUES: set[str] = {"*", "null"}

CORS_PROBE_PATHS: tuple[str, ...] = (
    "/",
    "/api/",
    "/api/v1/",
    "/v1/",
    "/graphql",
    "/rest/",
)