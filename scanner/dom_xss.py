import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanner.http_client import HttpClient


DANGEROUS_JS_SINKS = {
    "innerHTML": "Asignación directa a innerHTML puede permitir XSS si recibe entrada no confiable.",
    "outerHTML": "Asignación directa a outerHTML puede permitir XSS.",
    "document.write": "Uso de document.write puede facilitar XSS DOM.",
    "eval(": "Uso de eval permite ejecución dinámica de código.",
    "setTimeout(": "setTimeout con strings puede derivar en ejecución dinámica.",
    "setInterval(": "setInterval con strings puede derivar en ejecución dinámica.",
    "localStorage": "Datos persistidos en localStorage pueden ser manipulables por cliente.",
    "sessionStorage": "Datos en sessionStorage pueden influir en lógica cliente.",
    "location.hash": "Uso de location.hash puede originar XSS DOM si no se sanitiza.",
    "location.search": "Uso de query string en JS puede originar XSS DOM si no se sanitiza."
}

DOM_XSS_SOURCES = [
    "location.hash",
    "location.search",
    "location.href",
    "document.url",
    "document.documenturi",
    "document.referrer",
    "window.name",
    "localstorage",
    "sessionstorage",
]

HIGH_RISK_SINKS = {"eval(", "document.write", "innerHTML", "outerHTML", "setTimeout(", "setInterval("}


def tokenize_positions(text, token):
    token_lower = token.lower()
    content = (text or "").lower()
    positions = []
    start = 0

    while True:
        idx = content.find(token_lower, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1

    return positions


def has_source_sink_proximity(code, sources, sinks, distance=450):
    source_positions = []
    sink_positions = []

    for source in sources:
        source_positions.extend(tokenize_positions(code, source))

    for sink in sinks:
        sink_positions.extend(tokenize_positions(code, sink))

    if not source_positions or not sink_positions:
        return False

    return any(abs(src - sink) <= distance for src in source_positions for sink in sink_positions)


def scan_dom_xss(pages):
    client = HttpClient()
    results = []

    checked_scripts = set()

    for page in pages:
        html = page.get("html") or page.get("rendered_html") or ""
        page_url = page.get("url") or page.get("final_url") or ""
        if not html or not page_url:
            continue
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            continue

        sources = [("inline", html, page_url)]

        for script in soup.find_all("script", src=True):
            script_url = urljoin(page_url, script.get("src", ""))

            if script_url in checked_scripts:
                continue

            checked_scripts.add(script_url)

            try:
                response = client.get(script_url)

                if response.status_code == 200:
                    sources.append(("external", response.text, script_url))
            except Exception:
                continue

        for source_type, code, source_url in sources:
            code_lower = (code or "").lower()
            present_sinks = [sink for sink in DANGEROUS_JS_SINKS if sink.lower() in code_lower]
            present_sources = [source for source in DOM_XSS_SOURCES if source in code_lower]

            if present_sinks and present_sources:
                proximity = has_source_sink_proximity(code, present_sources, present_sinks)
                high_risk_detected = any(sink in HIGH_RISK_SINKS for sink in present_sinks)

                results.append({
                    "control": "Posible XSS DOM por correlación source/sink",
                    "status": "Posible hallazgo",
                    "severity": "Alta" if (proximity and high_risk_detected) else "Media",
                    "description": "Se detectaron fuentes controlables por usuario y sinks peligrosos en el mismo recurso JavaScript.",
                    "evidence": (
                        f"Fuente: {source_url} | Tipo: {source_type} | "
                        f"Sources: {', '.join(sorted(set(present_sources)))} | "
                        f"Sinks: {', '.join(sorted(set(present_sinks)))} | Proximidad: {proximity}"
                    ),
                    "recommendation": "Trazar el flujo source-to-sink, aplicar sanitización contextual y evitar ejecución dinámica de código."
                })
            elif present_sinks:
                for sink in present_sinks:
                    results.append({
                        "control": f"Sink DOM detectado: {sink}",
                        "status": "Comprobado",
                        "severity": "Baja",
                        "description": DANGEROUS_JS_SINKS[sink],
                        "evidence": f"Fuente: {source_url} | Tipo: {source_type}",
                        "recommendation": "Revisar si este sink recibe datos controlables por usuario antes de reportarlo como vulnerabilidad."
                    })

            # Angular bypass patterns
            if re.search(r"bypassSecurityTrust", code, re.IGNORECASE):
                results.append({
                    "control": "Angular DomSanitizer bypassSecurityTrust",
                    "status": "Posible hallazgo",
                    "severity": "Alta",
                    "description": "Uso de bypassSecurityTrust puede anular protecciones de sanitización de Angular.",
                    "evidence": f"Fuente: {source_url}",
                    "recommendation": "Revisar estrictamente el origen de datos y evitar bypass de sanitización salvo necesidad justificada."
                })

    if not results:
        results.append({
            "control": "XSS DOM",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron sinks peligrosos evidentes en HTML/JS accesible.",
            "evidence": "Sin patrones DOM XSS detectados.",
            "recommendation": "Complementar con análisis estático del repositorio frontend."
        })

    return results