from urllib.parse import urljoin, urlparse
from scanner.http_client import HttpClient


DEPENDENCY_EXPOSURE_PATHS = [
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/metrics",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/openapi.json",
    "/assets/",
    "/static/",
    "/main.js.map",
    "/vendor.js.map",
    "/runtime.js.map",
    "/polyfills.js.map"
]


def origin(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def scan_dependency_exposure(url):
    client = HttpClient()
    base = origin(url)
    results = []

    for path in DEPENDENCY_EXPOSURE_PATHS:
        target = urljoin(base, path)

        try:
            response = client.get(target)
            body = response.text or ""
            lower = body.lower()

            if response.status_code == 200:
                if path.endswith(".map"):
                    results.append({
                        "control": f"Source map expuesto: {path}",
                        "status": "Hallazgo",
                        "severity": "Alta",
                        "description": "Archivo source map expuesto públicamente. Puede revelar código fuente frontend.",
                        "evidence": f"URL: {target} | Tamaño: {len(body)}",
                        "recommendation": "No publicar source maps en producción o restringir acceso."
                    })

                elif "openapi" in lower or "swagger" in lower or "paths" in lower:
                    results.append({
                        "control": f"Documentación API expuesta: {path}",
                        "status": "Posible hallazgo",
                        "severity": "Media",
                        "description": "Documentación OpenAPI/Swagger accesible públicamente.",
                        "evidence": f"URL: {target}",
                        "recommendation": "Restringir documentación API o protegerla mediante autenticación."
                    })

                elif "propertysources" in lower or "beans" in lower or "metrics" in lower:
                    results.append({
                        "control": f"Actuator expuesto: {path}",
                        "status": "Hallazgo",
                        "severity": "Alta",
                        "description": "Endpoint Spring Actuator sensible accesible.",
                        "evidence": f"URL: {target}",
                        "recommendation": "Restringir Actuator, limitar endpoints y exigir autenticación."
                    })

        except Exception:
            continue

    if not results:
        results.append({
            "control": "Exposición de dependencias/runtime",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectó exposición pública de Actuator, Swagger sensible o source maps comunes.",
            "evidence": "Sin exposición detectada.",
            "recommendation": "Complementar con inventario de dependencias y revisión de configuración de despliegue."
        })

    return results