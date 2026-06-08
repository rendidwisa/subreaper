# ── Ghost IP detection signals ─────────────────────────────────────────────

ADMIN_SIGNALS = [
    "phpmyadmin", "jenkins", "grafana", "kibana", "portainer", "traefik",
]

DEFAULT_SIGNALS = [
    "welcome to nginx",
    "apache2 ubuntu default page",
    "iis windows server",
]

ERROR_SIGNALS = [
    "404 not found",
    "403 forbidden",
    "401 unauthorized",
]