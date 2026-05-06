from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient


PATH_PARAM_HINTS = ["file", "path", "download", "document", "doc", "template", "name", "filename"]

TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "..\\..\\windows\\win.ini"
]

SIGNATURES = [
    "root:x:0:0",
    "[fonts]",
    "[extensions]"
]


def scan_path_traversal(pages):
    client = HttpClient()
    results = []

    for page in pages:
        parsed = urlparse(page["url"])
        params = parse_qs(parsed.query)

        if not params:
            continue

        for param in params:
            if param.lower() not in PATH_PARAM_HINTS:
                continue

            for payload in TRAVERSAL_PAYLOADS:
                mutated = params.copy()
                mutated[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))

                try:
                    response = client.get(test_url)
                    body = response.text or ""

                    if any(sig in body for sig in SIGNATURES):
                        results.append({
                            "control": f"Path Traversal: {param}",
                            "status": "Hallazgo",
                            "severity": "Crítica",
                            "description": "Se detectó contenido compatible con lectura de archivo local.",
                            "evidence": f"URL: {test_url} | Firma detectada",
                            "recommendation": "Normalizar rutas, aplicar allowlist, aislar directorios y evitar acceso directo a rutas de usuario."
                        })
                        break

                except Exception:
                    continue

    if not results:
        results.append({
            "control": "Path Traversal",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron indicios de path traversal en parámetros analizados.",
            "evidence": "Sin firmas de archivos locales.",
            "recommendation": "Complementar con endpoints autenticados de descarga o generación documental."
        })

    return results