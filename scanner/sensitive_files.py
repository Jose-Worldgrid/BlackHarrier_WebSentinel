from urllib.parse import urljoin, urlparse
from scanner.http_client import HttpClient
import uuid


SENSITIVE_PATHS = [
    ".env", ".git/config", "backup.zip", "backup.sql", "db.sql",
    "config.php", "phpinfo.php", "server-status",
    "actuator", "actuator/env", "actuator/health",
    "swagger-ui.html", "swagger/index.html", "v3/api-docs",
    "api-docs", "robots.txt", "sitemap.xml",
    "security.txt", ".well-known/security.txt"
]


SIGNATURES = {
    ".env": ["DB_", "DATABASE_", "SECRET", "TOKEN", "PASSWORD", "APP_KEY", "AWS_"],
    ".git/config": ["[core]", "[remote", "repositoryformatversion"],
    "backup.sql": ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
    "db.sql": ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
    "phpinfo.php": ["PHP Version", "phpinfo()"],
    "actuator": ["_links", "health", "beans", "env"],
    "actuator/env": ["propertySources", "activeProfiles"],
    "actuator/health": ["status", "UP", "DOWN"],
    "swagger-ui.html": ["swagger", "SwaggerUIBundle", "openapi"],
    "swagger/index.html": ["swagger", "SwaggerUIBundle", "openapi"],
    "v3/api-docs": ["openapi", "paths", "components"],
    "api-docs": ["swagger", "openapi", "paths"],
    "robots.txt": ["User-agent", "Disallow", "Allow"],
    "sitemap.xml": ["<urlset", "<sitemapindex", "<loc>"],
    "security.txt": ["Contact:", "Expires:", "Encryption:"],
    ".well-known/security.txt": ["Contact:", "Expires:", "Encryption:"],
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
                    results.append({
                        "control": f"Recurso sensible: {path}",
                        "status": "Comprobado",
                        "severity": "Informativa",
                        "description": "Ruta comprobada sin exposición confirmada.",
                        "evidence": f"URL: {target} | Status: {response.status_code}",
                        "recommendation": "Sin acción requerida."
                    })
                    continue

                same_as_404 = (
                    baseline_status == response.status_code
                    and abs(body_len - baseline_len) < 50
                    and similarity(body, baseline_body) > 0.90
                )

                if same_as_404:
                    results.append({
                        "control": f"Recurso sensible: {path}",
                        "status": "Comprobado",
                        "severity": "Informativa",
                        "description": "Respuesta compatible con soft-404. No se confirma exposición real del recurso.",
                        "evidence": f"URL: {target} | Status: {response.status_code} | Tamaño similar a ruta inexistente",
                        "recommendation": "No reportar como vulnerabilidad salvo confirmación manual."
                    })
                    continue

                if not has_signature(path, body):
                    results.append({
                        "control": f"Recurso sensible: {path}",
                        "status": "Comprobado",
                        "severity": "Informativa",
                        "description": "La ruta responde, pero no contiene firmas propias del recurso esperado.",
                        "evidence": f"URL: {target} | Status: {response.status_code} | Sin firma sensible",
                        "recommendation": "Validar manualmente si el contenido es relevante."
                    })
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
                results.append({
                    "control": f"Recurso sensible: {path}",
                    "status": "Error",
                    "severity": "Informativa",
                    "description": "No se pudo comprobar la ruta.",
                    "evidence": str(exc),
                    "recommendation": "Revisar conectividad si aplica."
                })

    return results