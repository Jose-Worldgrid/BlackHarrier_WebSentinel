from urllib.parse import urljoin, urlparse
from scanner.http_client import HttpClient
import uuid


SENSITIVE_PATHS = [
    # Secrets & config
    ".env", ".env.local", ".env.prod", ".env.production", ".env.backup",
    ".env.example", ".env.development",
    "config.php", "config.js", "config.json", "config.yaml", "config.yml",
    "settings.py", "settings.php", "application.properties", "application.yml",
    "secrets.json", "credentials.json", "appsettings.json",
    # VCS
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    ".svn/entries", ".hg/hgrc",
    # Backups
    "backup.zip", "backup.sql", "backup.tar.gz", "backup.tgz",
    "db.sql", "database.sql", "dump.sql", "data.sql",
    "site.zip", "www.zip", "archive.zip", "old.zip",
    "backup.bak", "index.php.bak", "config.php.bak",
    # Debug & admin
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "server-status", "server-info",
    "console", "admin/console", "rails/info/properties",
    "wp-config.php", "wp-config.php.bak", "wp-login.php",
    # Spring Boot / Java
    "actuator", "actuator/env", "actuator/health", "actuator/beans",
    "actuator/mappings", "actuator/httptrace", "actuator/logfile",
    "actuator/heapdump", "actuator/threaddump", "actuator/conditions",
    # API docs
    "swagger-ui.html", "swagger/index.html", "swagger-ui/index.html",
    "v3/api-docs", "api-docs", "openapi.json", "openapi.yaml",
    "api/swagger.json", "api/v1/swagger.json",
    # Public recon
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "security.txt", ".well-known/security.txt",
    "humans.txt", "crossdomain.xml", "clientaccesspolicy.xml",
    # Logs
    "logs/access.log", "logs/error.log", "log/app.log",
    "error_log", "access_log",
    # Cloud
    ".aws/credentials", ".aws/config",
    "docker-compose.yml", "docker-compose.yaml",
    "Dockerfile", ".dockerignore",
    "Procfile", "app.yaml", "app.json",
    # Misc
    "package.json", "package-lock.json", "yarn.lock",
    "composer.json", "composer.lock",
    "Gemfile", "Gemfile.lock",
    "requirements.txt", "Pipfile",
]

SIGNATURES = {
    ".env":                  ["DB_", "DATABASE_", "SECRET", "TOKEN", "PASSWORD", "APP_KEY", "AWS_", "API_KEY"],
    ".env.local":            ["DB_", "SECRET", "TOKEN", "PASSWORD", "API_KEY"],
    ".env.prod":             ["DB_", "SECRET", "TOKEN", "PASSWORD", "API_KEY"],
    ".env.production":       ["DB_", "SECRET", "TOKEN", "PASSWORD", "API_KEY"],
    ".env.backup":           ["DB_", "SECRET", "TOKEN"],
    ".env.development":      ["DB_", "SECRET", "TOKEN"],
    "config.php":            ["<?php", "DB_", "password", "secret"],
    "config.json":           ["password", "secret", "token", "apikey", "api_key"],
    "secrets.json":          ["password", "secret", "token"],
    "credentials.json":      ["client_id", "client_secret", "private_key"],
    "appsettings.json":      ["ConnectionStrings", "Password", "Secret"],
    "settings.py":           ["SECRET_KEY", "DATABASE", "PASSWORD"],
    "application.properties":["spring.datasource", "password", "secret"],
    ".git/config":           ["[core]", "[remote", "repositoryformatversion"],
    ".git/HEAD":             ["ref:", "HEAD"],
    ".svn/entries":          ["svn"],
    "backup.sql":            ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
    "db.sql":                ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
    "database.sql":          ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
    "dump.sql":              ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
    "phpinfo.php":           ["PHP Version", "phpinfo()"],
    "info.php":              ["PHP Version", "phpinfo()"],
    "server-status":         ["Apache Server Status", "requests currently being processed"],
    "actuator":              ["_links", "health", "beans", "env"],
    "actuator/env":          ["propertySources", "activeProfiles"],
    "actuator/health":       ["status", "UP", "DOWN"],
    "actuator/heapdump":     ["JAVA PROFILE"],
    "swagger-ui.html":       ["swagger", "SwaggerUIBundle", "openapi"],
    "v3/api-docs":           ["openapi", "paths", "components"],
    "api-docs":              ["swagger", "openapi", "paths"],
    "openapi.json":          ["openapi", "paths"],
    "openapi.yaml":          ["openapi:", "paths:"],
    "robots.txt":            ["User-agent", "Disallow", "Allow"],
    "sitemap.xml":           ["<urlset", "<sitemapindex", "<loc>"],
    "security.txt":          ["Contact:", "Expires:", "Encryption:"],
    ".well-known/security.txt": ["Contact:", "Expires:"],
    "package.json":          ["dependencies", "devDependencies", "scripts"],
    "composer.json":         ["require", "autoload"],
    ".aws/credentials":      ["aws_access_key_id", "aws_secret_access_key"],
    "docker-compose.yml":    ["services:", "image:", "environment:"],
    "docker-compose.yaml":   ["services:", "image:", "environment:"],
    "wp-config.php":         ["DB_NAME", "DB_PASSWORD", "AUTH_KEY"],
}


def origin_base(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0

    shorter = min(len(a), len(b))
    longer = max(len(a), len(b))

    if longer == 0:
        return 0.0

    return shorter / longer if a[:300] == b[:300] else 0.0


def get_soft_404_baseline(client, base_url):
    random_path = f"__webaudit_nonexistent_{uuid.uuid4().hex}.txt"
    response = client.get(urljoin(base_url, random_path))
    return response.status_code, response.text or "", len(response.text or "")


def has_signature(path, body):
    signatures = SIGNATURES.get(path)

    if not signatures:
        return False

    upper = body.upper()
    return any(sig.upper() in upper for sig in signatures)


def scan_sensitive_files(url: str):
    client = HttpClient()
    results = []
    checked_without_exposure = []
    check_errors = []

    bases = list(dict.fromkeys([
        origin_base(url),
        url.rstrip("/") + "/"
    ]))

    for base in bases:
        try:
            baseline_status, baseline_body, baseline_len = get_soft_404_baseline(client, base)
        except Exception:
            baseline_status, baseline_body, baseline_len = None, "", 0

        for path in SENSITIVE_PATHS:
            target = urljoin(base, path)

            try:
                response = client.get(target)
                body = response.text or ""
                body_len = len(body)

                if response.status_code not in [200, 201, 202, 206]:
                    checked_without_exposure.append((path, target, response.status_code, "status_non_exposed"))
                    continue

                same_as_404 = (
                    baseline_status == response.status_code
                    and abs(body_len - baseline_len) < 50
                    and similarity(body, baseline_body) > 0.90
                )

                if same_as_404:
                    checked_without_exposure.append((path, target, response.status_code, "soft_404_like"))
                    continue

                if not has_signature(path, body):
                    checked_without_exposure.append((path, target, response.status_code, "no_signature"))
                    continue

                severity = "Alta" if path in [".env", ".git/config", "backup.sql", "db.sql"] else "Media"

                results.append({
                    "control": f"Recurso sensible expuesto: {path}",
                    "status": "Hallazgo",
                    "severity": severity,
                    "description": "Se confirmó contenido compatible con recurso sensible accesible.",
                    "evidence": f"URL: {target} | Status: {response.status_code} | Tamaño: {body_len}",
                    "recommendation": "Restringir acceso, eliminar el recurso publicado y revisar configuración de despliegue."
                })

            except Exception as exc:
                check_errors.append((path, str(exc)))

    if checked_without_exposure:
        samples = []
        for path, target, status_code, reason in checked_without_exposure[:15]:
            samples.append(f"{status_code} {path} ({reason})")

        results.append({
            "control": "Recursos sensibles (resumen)",
            "status": "Comprobado",
            "severity": "Informativa",
            "description": f"Se comprobaron {len(checked_without_exposure)} rutas sin exposición sensible confirmada.",
            "evidence": " | ".join(samples),
            "recommendation": "Sin acción requerida para estas rutas; mantener hardening y monitorización."
        })

    if check_errors:
        samples = []
        for path, err in check_errors[:8]:
            samples.append(f"{path}: {err}")

        results.append({
            "control": "Recursos sensibles (errores de comprobación)",
            "status": "Error",
            "severity": "Informativa",
            "description": f"{len(check_errors)} comprobaciones de rutas sensibles finalizaron con error técnico.",
            "evidence": " | ".join(samples),
            "recommendation": "Reintentar comprobación y revisar conectividad/proxy/SSL si aplica."
        })

    return results