from urllib.parse import urljoin
from scanner.http_client import HttpClient


COMMON_DIRS = [
    "uploads/",
    "files/",
    "backup/",
    "backups/",
    "logs/",
    "tmp/",
    "static/",
    "assets/"
]


def scan_directory_listing(url: str):
    client = HttpClient()
    results = []
    base = url.rstrip("/") + "/"

    signatures = [
        "Index of /",
        "Directory Listing",
        "Parent Directory",
        "<title>Index of"
    ]

    for directory in COMMON_DIRS:
        target = urljoin(base, directory)

        try:
            response = client.get(target)

            if response.status_code == 200 and any(sig.lower() in response.text.lower() for sig in signatures):
                results.append({
                    "control": f"Directory Listing: {directory}",
                    "status": "Hallazgo",
                    "severity": "Media",
                    "description": "Directorio navegable públicamente.",
                    "evidence": f"URL: {target}",
                    "recommendation": "Deshabilitar directory listing y restringir acceso a directorios internos."
                })

        except Exception:
            continue

    if not results:
        results.append({
            "control": "Directory Listing",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectó listado de directorios en rutas comunes.",
            "evidence": "Rutas comunes revisadas.",
            "recommendation": "Mantener directory listing deshabilitado."
        })

    return results