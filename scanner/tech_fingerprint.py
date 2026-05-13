import re
import logging
from bs4 import BeautifulSoup
from scanner.http_client import HttpClient


logger = logging.getLogger(__name__)


KNOWN_CLIENT_LIBS = {
    "jquery": {
        "pattern": r"jquery[-.]([0-9]+\.[0-9]+\.[0-9]+)",
        "risk": "Versiones antiguas de jQuery pueden estar asociadas a XSS, prototype pollution o vulnerabilidades DOM."
    },
    "bootstrap": {
        "pattern": r"bootstrap[-.]([0-9]+\.[0-9]+\.[0-9]+)",
        "risk": "Versiones antiguas de Bootstrap pueden contener vulnerabilidades XSS."
    },
    "angular": {
        "pattern": r"angular[-.]([0-9]+\.[0-9]+\.[0-9]+)",
        "risk": "Versiones antiguas de Angular pueden estar asociadas a bypass de sanitización o XSS."
    },
    "chart.js": {
        "pattern": r"chart(?:\.min)?\.js",
        "risk": "Chart.js aparece como componente sensible en el análisis de dependencias frontend."
    },
    "moment": {
        "pattern": r"moment(?:\.min)?\.js",
        "risk": "Moment.js legacy puede incrementar deuda técnica y exposición en frontend."
    }
}


SERVER_TECH_HINTS = [
    "tomcat",
    "spring",
    "reactor",
    "netty",
    "jetty",
    "nginx",
    "apache",
    "express",
    "node"
]


def scan_technology_fingerprint(url: str, pages):
    client = HttpClient()
    results = []

    try:
        response = client.get(url)
        headers_text = " ".join([f"{k}: {v}" for k, v in response.headers.items()]).lower()

        server_hits = [x for x in SERVER_TECH_HINTS if x in headers_text]

        if server_hits:
            results.append({
                "control": "Fingerprinting de tecnología servidor",
                "status": "Detectado",
                "severity": "Media",
                "description": "Se identificaron tecnologías de servidor expuestas en cabeceras HTTP.",
                "evidence": ", ".join(server_hits),
                "recommendation": "Reducir banners, ocultar versiones y revisar exposición de stack tecnológico."
            })

    except Exception:
        logger.debug("Fallo en fingerprinting de cabeceras servidor", exc_info=True)

    detected = []

    for page in (pages or [])[:100]:
        html_content = page.get("html") or ""
        page_url = page.get("url") or page.get("final_url") or ""
        if not html_content:
            continue

        soup = BeautifulSoup(html_content, "html.parser")

        scripts = []
        for script in soup.find_all("script", src=True):
            src = script.get("src", "")
            if src:
                scripts.append(src)

        html_blob = html_content + " " + " ".join(scripts)

        for lib, meta in KNOWN_CLIENT_LIBS.items():
            match = re.search(meta["pattern"], html_blob, re.IGNORECASE)
            if match:
                detected.append((lib, match.group(0), page_url, meta["risk"]))

    seen = set()
    for lib, evidence, page_url, risk in detected:
        key = (lib, evidence)
        if key in seen:
            continue
        seen.add(key)

        results.append({
            "control": f"Dependencia frontend detectada: {lib}",
            "status": "Detectado",
            "severity": "Media",
            "description": risk,
            "evidence": f"{evidence} | Página: {page_url}",
            "recommendation": "Validar versión exacta contra inventario SBOM/Dependency Check y actualizar si procede."
        })

    if not results:
        results.append({
            "control": "Fingerprinting tecnológico ampliado",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron tecnologías o librerías relevantes en el alcance público.",
            "evidence": "Sin coincidencias relevantes.",
            "recommendation": "Complementar con análisis autenticado y revisión de artefactos estáticos."
        })

    return results