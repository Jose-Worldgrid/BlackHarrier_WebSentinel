"""
Server-Side Template Injection (SSTI) scanner.
Tests form fields and GET parameters for template evaluation.
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
from scanner.http_client import HttpClient
from scanner.forms import extract_forms_from_html


logger = logging.getLogger(__name__)


# Each entry: (payload, expected_result_string, engine_hint)
SSTI_PROBES = [
    # Jinja2 / Twig / Flask
    ("{{7*7}}",           "49",  "Jinja2/Twig"),
    ("{{7*'7'}}",         "7777777", "Jinja2"),
    ("{%25 7*7 %25}",     "49",  "Jinja2 (URL-encoded)"),
    # Freemarker / Spring
    ("${7*7}",            "49",  "Freemarker/Spring EL"),
    ("#{7*7}",            "49",  "Spring EL"),
    # Ruby ERB / Slim
    ("<%= 7*7 %>",        "49",  "Ruby ERB"),
    # Smarty
    ("{7*7}",             "49",  "Smarty"),
    # Pebble / Velocity
    ("${{7*7}}",          "49",  "Pebble/Velocity"),
    # Mako
    ("${7*7}",            "49",  "Mako"),
    # Handlebars
    ("{{#with \"s\" as |string|}}{{string.constructor \"return 7*7\"}}{{/with}}", "49", "Handlebars"),
    # Tornado / Python exec hint
    ("{% print(7*7) %}",  "49",  "Tornado"),
]


def _check_template_exec(response_text, expected):
    return expected in (response_text or "")


def _probe_forms(client, forms, results):
    for form in forms:
        method = str(form.get("method", "GET")).upper()
        action = form.get("action")
        if not action:
            continue

        for probe, expected, engine in SSTI_PROBES:
            data = {}
            for field in form.get("fields", []):
                fname = field.get("name") or field.get("id") or ""
                if not fname:
                    continue
                ftype = (field.get("type") or "").lower()
                if ftype in ("submit", "button", "reset", "file"):
                    continue
                if ftype == "hidden":
                    data[fname] = field.get("value", "")
                else:
                    data[fname] = probe

            if not data:
                continue

            try:
                if method == "POST":
                    r = client.post(action, data=data)
                else:
                    r = client.get(action, params=data)

                if r and _check_template_exec(r.text, expected):
                    results.append({
                        "control": f"SSTI ({engine}) - formulario {form.get('index', '?')}",
                        "status": "Hallazgo",
                        "severity": "Crítica",
                        "description": (
                            f"El motor de plantillas evaluó la expresión matemática: "
                            f"'{probe}' → '{expected}'. Ejecución de código remoto probable."
                        ),
                        "evidence": (
                            f"URL: {action} | Payload: {probe} | "
                            f"Resultado esperado: {expected} | Motor inferido: {engine}"
                        ),
                        "recommendation": (
                            "Nunca renderizar entrada de usuario directamente como plantilla. "
                            "Usar sandboxing estricto, escapar variables y considerar migrar a "
                            "soluciones sin eval dinámico de plantillas."
                        ),
                    })
                    return  # one finding per form is enough
            except Exception:
                logger.debug("Fallo en prueba SSTI de formulario", exc_info=True)


def _probe_get_params(client, page, results):
    page_url = page.get("url") or page.get("final_url") or ""
    if not page_url:
        return

    parsed = urlparse(page_url)
    params = parse_qs(parsed.query)
    if not params:
        return

    for param in list(params.keys()):
        for probe, expected, engine in SSTI_PROBES:
            mutated = params.copy()
            mutated[param] = probe
            test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
            try:
                r = client.get(test_url)
                if r and _check_template_exec(r.text, expected):
                    results.append({
                        "control": f"SSTI ({engine}) - parámetro GET: {param}",
                        "status": "Hallazgo",
                        "severity": "Crítica",
                        "description": (
                            f"Motor de plantillas evaluó expresión aritmética en parámetro GET. "
                            f"'{probe}' → '{expected}'. RCE probable."
                        ),
                        "evidence": (
                            f"URL: {test_url} | Param: {param} | "
                            f"Payload: {probe} | Motor: {engine}"
                        ),
                        "recommendation": (
                            "No interpolar parámetros de usuario en plantillas. "
                            "Aplicar codificación de entrada y revisar toda lógica de renderizado."
                        ),
                    })
                    return
            except Exception:
                logger.debug("Fallo en prueba SSTI de parametro GET", exc_info=True)


def scan_ssti(pages):
    client = HttpClient()
    results = []

    for page in pages:
        page_url = page.get("url") or page.get("final_url") or ""
        page_html = page.get("html") or page.get("rendered_html") or ""
        if not page_url:
            continue

        forms = extract_forms_from_html(page_url, page_html)
        _probe_forms(client, forms, results)
        _probe_get_params(client, page, results)

    if not results:
        results.append({
            "control": "Server-Side Template Injection (SSTI)",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectó evaluación de expresiones de plantilla en los vectores analizados.",
            "evidence": "Sin respuesta con resultado aritmético evaluado.",
            "recommendation": (
                "Complementar con revisión de código fuente y pruebas autenticadas. "
                "Prestar atención a rutas que reciban parámetros usados en generación de HTML dinámico."
            ),
        })

    return results
