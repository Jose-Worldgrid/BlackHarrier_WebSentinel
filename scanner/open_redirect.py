from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient


REDIRECT_PARAM_NAMES = [
    "next", "url", "redirect", "redirect_uri", "return", "returnUrl",
    "continue", "target", "dest", "destination", "callback"
]


def scan_open_redirect_pages(pages):
    client = HttpClient()
    results = []
    test_domain = "https://example.org"

    for page in pages:
        page_url = page.get("url") or page.get("final_url") or ""
        if not page_url:
            continue
        parsed = urlparse(page_url)
        params = parse_qs(parsed.query)

        if not params:
            continue

        redirect_like = [p for p in params.keys() if p.lower() in [x.lower() for x in REDIRECT_PARAM_NAMES]]

        for param in redirect_like:
            mutated = params.copy()
            mutated[param] = test_domain

            test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))

            try:
                response = client.get(test_url)

                final_url = response.url

                if final_url.startswith(test_domain):
                    results.append({
                        "control": "Open Redirect",
                        "status": "Posible hallazgo",
                        "severity": "Media",
                        "description": "Parámetro de redirección permite destino externo.",
                        "evidence": f"URL probada: {test_url} | URL final: {final_url}",
                        "recommendation": "Validar destinos contra lista blanca y evitar redirecciones arbitrarias."
                    })

            except Exception:
                continue

    if not results:
        results.append({
            "control": "Open Redirect",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron redirecciones abiertas en parámetros analizados.",
            "evidence": "Sin redirección externa confirmada.",
            "recommendation": "Revisar manualmente flujos de login, logout y callbacks."
        })

    return results