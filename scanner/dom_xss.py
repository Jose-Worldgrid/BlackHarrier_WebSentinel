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


def scan_dom_xss(pages):
    client = HttpClient()
    results = []

    checked_scripts = set()

    for page in pages:
        html = page["html"]
        soup = BeautifulSoup(html, "html.parser")

        sources = [("inline", html, page["url"])]

        for script in soup.find_all("script", src=True):
            script_url = urljoin(page["url"], script["src"])

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
            for sink, explanation in DANGEROUS_JS_SINKS.items():
                if sink in code:
                    results.append({
                        "control": f"Posible sink XSS DOM: {sink}",
                        "status": "Posible hallazgo",
                        "severity": "Media" if sink not in ["eval(", "document.write"] else "Alta",
                        "description": explanation,
                        "evidence": f"Fuente: {source_url} | Tipo: {source_type}",
                        "recommendation": "Revisar flujo de datos, aplicar sanitización, Trusted Types y evitar sinks peligrosos."
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