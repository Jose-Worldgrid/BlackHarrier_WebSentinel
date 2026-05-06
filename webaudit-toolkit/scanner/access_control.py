from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient


SENSITIVE_ENDPOINTS = [
    "/admin",
    "/administrator",
    "/dashboard",
    "/management",
    "/actuator",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/metrics",
    "/api/users",
    "/api/admin",
    "/api/v1/users",
    "/api/v1/admin",
    "/swagger-ui.html",
    "/v3/api-docs"
]


def origin(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def mutate_numeric_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    candidates = []

    for key, values in params.items():
        if not values:
            continue

        value = values[0]

        if value.isdigit():
            for replacement in ["0", "1", "2", "999999"]:
                mutated = params.copy()
                mutated[key] = replacement
                candidates.append(urlunparse(parsed._replace(query=urlencode(mutated, doseq=True))))

    return candidates


def scan_access_control(target_url, pages, client=None):
    client = client or HttpClient()
    results = []
    base = origin(target_url)

    # 1. Sensitive endpoints
    for endpoint in SENSITIVE_ENDPOINTS:
        url = base + endpoint

        try:
            response = client.get(url)
            content_type = response.headers.get("Content-Type", "")

            if response.status_code == 200 and "text/html" not in content_type.lower():
                results.append({
                    "control": f"Endpoint sensible accesible: {endpoint}",
                    "status": "Posible hallazgo",
                    "severity": "Alta",
                    "description": "Endpoint sensible accesible con respuesta no HTML genérica.",
                    "evidence": f"URL: {url} | Status: {response.status_code} | Content-Type: {content_type} | Tamaño: {len(response.text or '')}",
                    "recommendation": "Revisar autenticación/autorización y restringir endpoints administrativos."
                })

            elif response.status_code == 200 and any(x in response.text.lower() for x in ["users", "admin", "actuator", "swagger", "openapi", "management"]):
                results.append({
                    "control": f"Endpoint sensible potencialmente expuesto: {endpoint}",
                    "status": "Posible hallazgo",
                    "severity": "Alta",
                    "description": "Endpoint sensible devuelve contenido compatible con funcionalidad interna.",
                    "evidence": f"URL: {url} | Status: {response.status_code}",
                    "recommendation": "Validar control de acceso, autenticación y exposición de documentación/API."
                })

        except Exception:
            continue

    # 2. IDOR-like numeric parameter probing
    for page in pages:
        for mutated_url in mutate_numeric_params(page["url"]):
            try:
                response = client.get(mutated_url)

                if response.status_code == 200 and len(response.text or "") > 100:
                    results.append({
                        "control": "Prueba básica de control de acceso por parámetro",
                        "status": "Comprobado",
                        "severity": "Media",
                        "description": "Parámetro numérico modificado devuelve respuesta válida. Requiere revisión manual para descartar IDOR.",
                        "evidence": f"URL modificada: {mutated_url} | Status: {response.status_code} | Tamaño: {len(response.text or '')}",
                        "recommendation": "Validar autorización server-side por objeto/recurso, no solo por sesión."
                    })
            except Exception:
                continue

    if not results:
        results.append({
            "control": "Control de acceso",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron endpoints sensibles expuestos ni indicios básicos de IDOR.",
            "evidence": "Sin exposición confirmada.",
            "recommendation": "Complementar con pruebas autenticadas multi-rol."
        })

    return results