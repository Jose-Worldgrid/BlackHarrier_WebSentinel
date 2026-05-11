from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanner.http_client import HttpClient


API_HINTS = ["/api/", "/graphql", "/v1/", "/v2/", "/swagger", "/openapi", "/api-docs"]


def scan_api_discovery(url: str, pages):
    client = HttpClient()
    results = []
    discovered = set()

    for page in pages:
        page_url  = page.get("url") or page.get("final_url") or ""
        page_html = page.get("html") or page.get("rendered_html") or ""
        if not page_url or not page_html:
            continue

        try:
            soup = BeautifulSoup(page_html, "html.parser")
        except Exception:
            continue

        for tag in soup.find_all(["a", "script"], href=True):
            href = tag.get("href") or ""
            if href:
                full = urljoin(page_url, href)
                if any(hint in full.lower() for hint in API_HINTS):
                    discovered.add(full)

        for tag in soup.find_all("script", src=True):
            src_val = tag.get("src") or ""
            if src_val:
                src = urljoin(page_url, src_val)
                if any(hint in src.lower() for hint in API_HINTS):
                    discovered.add(src)

    common_api_paths = [
        "api/",
        "api/v1/",
        "graphql",
        "swagger-ui.html",
        "v3/api-docs",
        "openapi.json"
    ]

    base = url.rstrip("/") + "/"

    for path in common_api_paths:
        target = urljoin(base, path)

        try:
            response = client.get(target)

            if response.status_code in [200, 401, 403]:
                discovered.add(f"{target} [{response.status_code}]")

        except Exception:
            continue

    if discovered:
        results.append({
            "control": "Descubrimiento de API",
            "status": "Detectado",
            "severity": "Media",
            "description": "Se detectaron rutas o artefactos potencialmente asociados a APIs.",
            "evidence": " | ".join(list(discovered)[:20]),
            "recommendation": "Revisar autenticación, autorización, rate limiting y exposición de documentación API."
        })
    else:
        results.append({
            "control": "Descubrimiento de API",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron rutas API comunes en el alcance analizado.",
            "evidence": "Sin rutas API identificadas.",
            "recommendation": "Validar manualmente APIs internas o autenticadas."
        })

    return results