from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient
from scanner.forms import extract_forms_from_html


XSS_PAYLOADS = [
    "WEB_AUDIT_XSS_MARKER_12345",
    "\"><WEB_AUDIT_XSS_MARKER>",
    "'><WEB_AUDIT_XSS_MARKER>"
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
        forms = extract_forms_from_html(page["url"], page["html"])

        for form in forms:
            for payload in payloads:
                try:
                    response = submit_form(client, form, payload)

                    if payload in response.text:
                        results.append({
                            "control": f"XSS reflejado - formulario {form['index']}",
                            "status": "Posible hallazgo",
                            "severity": "Alta",
                            "description": "Entrada reflejada sin neutralización evidente.",
                            "evidence": f"URL: {form['action']} | Payload reflejado: {payload}",
                            "recommendation": "Aplicar codificación de salida contextual, sanitización y CSP restrictiva."
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
                response = test_query_params(client, page["url"], payload)

                if response and payload in response.text:
                    results.append({
                        "control": "XSS reflejado - parámetro GET",
                        "status": "Posible hallazgo",
                        "severity": "Alta",
                        "description": "Parámetro GET reflejado en la respuesta.",
                        "evidence": f"URL: {page['url']} | Payload reflejado: {payload}",
                        "recommendation": "Codificar salida, validar parámetros y aplicar CSP."
                    })
                    break

            except Exception:
                pass

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