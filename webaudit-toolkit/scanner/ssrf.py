from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient


SSRF_PARAM_HINTS = [
    "url", "uri", "endpoint", "target", "dest", "destination",
    "callback", "webhook", "image", "file", "path", "proxy", "redirect"
]


def scan_ssrf_hints(pages):
    client = HttpClient()
    results = []

    test_value = "https://example.org/"

    for page in pages:
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)

        if not params:
            continue

        for param in params:
            if param.lower() not in SSRF_PARAM_HINTS:
                continue

            mutated = params.copy()
            mutated[param] = test_value
            test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))

            try:
                original = client.get(page["url"])
                tested = client.get(test_url)

                if tested.status_code != original.status_code or abs(len(tested.text or "") - len(original.text or "")) > 300:
                    results.append({
                        "control": f"Parámetro candidato a SSRF: {param}",
                        "status": "Posible hallazgo",
                        "severity": "Media",
                        "description": "Parámetro compatible con carga de URL externa produce respuesta diferencial.",
                        "evidence": f"URL: {test_url} | Status original: {original.status_code} | Status prueba: {tested.status_code}",
                        "recommendation": "Validar allowlist de destinos, bloquear IPs internas/metadatos y evitar fetch arbitrario server-side."
                    })
            except Exception:
                continue

    if not results:
        results.append({
            "control": "SSRF",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron parámetros candidatos a SSRF con respuesta diferencial.",
            "evidence": "Sin indicios.",
            "recommendation": "Complementar con revisión de código y pruebas autenticadas."
        })

    return results