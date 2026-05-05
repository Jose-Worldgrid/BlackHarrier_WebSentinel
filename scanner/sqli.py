from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
from scanner.http_client import HttpClient
from scanner.forms import extract_forms_from_html


SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql",
    "mariadb",
    "postgresql",
    "ora-",
    "sqlite",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
    "sqlstate",
    "jdbc",
    "odbc",
    "sql server",
    "microsoft ole db",
    "psql:",
    "postgres exception",
    "oracle error"
]


ERROR_PAYLOADS = [
    "'",
    "\"",
    "';",
    "\");"
]


BOOLEAN_TESTS = [
    {
        "name": "Boolean-based simple",
        "true": "' OR '1'='1",
        "false": "' AND '1'='2"
    },
    {
        "name": "Boolean-based doble comilla",
        "true": "\" OR \"1\"=\"1",
        "false": "\" AND \"1\"=\"2"
    },
    {
        "name": "Posible bypass de login",
        "true": "admin' OR '1'='1",
        "false": "admin' AND '1'='2"
    }
]


SUCCESS_INDICATORS = [
    "dashboard",
    "logout",
    "cerrar sesión",
    "cerrar sesion",
    "mi cuenta",
    "perfil",
    "admin",
    "panel",
    "bienvenido",
    "welcome"
]


FAILURE_INDICATORS = [
    "invalid",
    "incorrect",
    "error",
    "denied",
    "unauthorized",
    "no autorizado",
    "credenciales",
    "contraseña incorrecta",
    "usuario incorrecto",
    "login failed",
    "authentication failed"
]


def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


def detect_sql_errors(text):
    lower = text.lower()
    return [pattern for pattern in SQL_ERROR_PATTERNS if pattern in lower]


def build_form_data(form, payload):
    data = {}

    for field in form["fields"]:
        name = field["name"]
        field_type = field["type"]

        if field_type in ["submit", "button", "reset", "file"]:
            continue

        if field_type == "hidden":
            data[name] = field["value"]
        elif field_type == "email":
            data[name] = f"test{payload}@example.com"
        else:
            data[name] = payload

    return data


def submit_form(client, form, payload):
    data = build_form_data(form, payload)

    if not data:
        return None

    if form["method"] == "POST":
        return client.post(form["action"], data=data)

    return client.get(form["action"], params=data)


def analyze_boolean_difference(true_response, false_response):
    true_text = true_response.text.lower()
    false_text = false_response.text.lower()

    true_success = any(x in true_text for x in SUCCESS_INDICATORS)
    false_failure = any(x in false_text for x in FAILURE_INDICATORS)

    ratio = similarity(true_response.text, false_response.text)
    length_diff = abs(len(true_response.text) - len(false_response.text))
    status_diff = true_response.status_code != false_response.status_code

    if true_success and false_failure:
        return True, "Indicadores de acceso exitoso frente a respuesta fallida."

    if status_diff and ratio < 0.85:
        return True, f"Cambio de código HTTP y diferencia relevante. Similitud: {ratio:.2f}"

    if length_diff > 500 and ratio < 0.85:
        return True, f"Diferencia significativa de longitud. Diferencia: {length_diff} caracteres. Similitud: {ratio:.2f}"

    return False, f"Sin diferencia concluyente. Similitud: {ratio:.2f}, diferencia longitud: {length_diff}."


def mutate_url_param(url, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return None

    mutated = {k: payload for k in params.keys()}
    return urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))


def scan_sqli_pages(pages):
    client = HttpClient()
    results = []

    for page in pages:
        forms = extract_forms_from_html(page["url"], page["html"])

        for form in forms:
            for payload in ERROR_PAYLOADS:
                try:
                    response = submit_form(client, form, payload)
                    if not response:
                        continue

                    errors = detect_sql_errors(response.text)

                    if errors:
                        results.append({
                            "control": f"SQLi error-based - formulario {form['index']}",
                            "status": "Posible hallazgo",
                            "severity": "Alta",
                            "description": "Respuesta compatible con error SQL expuesto.",
                            "evidence": f"URL: {form['action']} | Payload: {payload} | Errores: {', '.join(errors)}",
                            "recommendation": "Usar consultas parametrizadas, ORM seguro y ocultar errores técnicos."
                        })

                except Exception as exc:
                    results.append({
                        "control": "SQLi error-based",
                        "status": "Error",
                        "severity": "Media",
                        "description": "Error durante prueba SQLi controlada.",
                        "evidence": str(exc),
                        "recommendation": "Revisar conectividad y comportamiento del formulario."
                    })

            for test in BOOLEAN_TESTS:
                try:
                    true_response = submit_form(client, form, test["true"])
                    false_response = submit_form(client, form, test["false"])

                    if not true_response or not false_response:
                        continue

                    vulnerable, evidence = analyze_boolean_difference(true_response, false_response)

                    if vulnerable:
                        results.append({
                            "control": f"{test['name']} - formulario {form['index']}",
                            "status": "Posible hallazgo",
                            "severity": "Crítica",
                            "description": "Comportamiento diferencial compatible con SQL Injection boolean-based o bypass de autenticación.",
                            "evidence": f"URL: {form['action']} | TRUE: {test['true']} | FALSE: {test['false']} | {evidence}",
                            "recommendation": "Revisar autenticación, aplicar queries parametrizadas y validación server-side."
                        })

                except Exception:
                    pass

        for payload in ERROR_PAYLOADS:
            try:
                test_url = mutate_url_param(page["url"], payload)
                if not test_url:
                    continue

                response = client.get(test_url)
                errors = detect_sql_errors(response.text)

                if errors:
                    results.append({
                        "control": "SQLi error-based - parámetro GET",
                        "status": "Posible hallazgo",
                        "severity": "Alta",
                        "description": "Parámetro GET provoca respuesta compatible con error SQL.",
                        "evidence": f"URL: {test_url} | Errores: {', '.join(errors)}",
                        "recommendation": "Validar parámetros, parametrizar consultas y ocultar errores técnicos."
                    })

            except Exception:
                pass

    if not results:
        results.append({
            "control": "SQL Injection",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron indicios concluyentes de SQL Injection en el alcance analizado.",
            "evidence": "Sin errores SQL ni diferencias booleanas concluyentes.",
            "recommendation": "Complementar con análisis autenticado, revisión de código y pruebas manuales."
        })

    return results