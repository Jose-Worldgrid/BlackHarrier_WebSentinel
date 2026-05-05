import time
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from scanner.payloads.sqli_payloads import SQLI_AUTH_PAYLOADS

from scanner.browser_auth import scan_browser_auth_sqli


ERROR_MARKERS = [
    "sql syntax",
    "mysql",
    "mariadb",
    "postgresql",
    "sqlite",
    "odbc",
    "jdbc",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
    "you have an error in your sql",
    "database error",
    "sqlstate",
]


SUCCESS_MARKERS = [
    "dashboard",
    "logout",
    "cerrar sesión",
    "perfil",
    "mi cuenta",
    "admin",
    "panel",
]


AUTH_KEYWORDS = [
    "login",
    "signin",
    "auth",
    "iniciar-sesion",
    "inicio-sesion",
]


def is_auth_page(page):
    url = str(page.get("url") or "").lower()
    final_url = str(page.get("final_url") or "").lower()
    classification = str(page.get("classification") or "").lower()

    return (
        classification == "auth"
        or any(x in url for x in AUTH_KEYWORDS)
        or any(x in final_url for x in AUTH_KEYWORDS)
    )


def extract_input_candidates(html):
    soup = BeautifulSoup(html or "", "html.parser")
    inputs = []

    for field in soup.find_all(["input", "textarea"]):
        field_type = (field.get("type") or "text").lower()
        name = field.get("name") or field.get("id") or field.get("placeholder")

        if not name:
            continue

        inputs.append({
            "name": name,
            "type": field_type,
        })

    return inputs


def infer_login_fields(inputs):
    user_field = None
    password_field = None

    for item in inputs:
        name = item["name"].lower()
        field_type = item["type"]

        if field_type == "password" or "pass" in name or "contraseña" in name:
            password_field = item["name"]

        if (
            field_type in ["email", "text"]
            or "email" in name
            or "user" in name
            or "usuario" in name
            or "login" in name
        ):
            if not user_field:
                user_field = item["name"]

    return user_field, password_field


def response_indicates_sqli(response_text):
    lower = (response_text or "").lower()
    return any(marker in lower for marker in ERROR_MARKERS)


def response_indicates_possible_login(response_text, final_url):
    lower = (response_text or "").lower()
    final_lower = (final_url or "").lower()

    return (
        any(marker in lower for marker in SUCCESS_MARKERS)
        or any(marker in final_lower for marker in ["dashboard", "panel", "admin", "account", "profile"])
    )


def build_result(control, status, severity, description, evidence, recommendation):
    return {
        "control": control,
        "status": status,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def test_html_login_sqli(client, page, username_value="test@example.com"):
    url = page.get("final_url") or page.get("url")
    html = page.get("html") or ""

    inputs = extract_input_candidates(html)
    user_field, password_field = infer_login_fields(inputs)

    if not user_field or not password_field:
        return build_result(
            "SQLi en login HTML",
            "No probado",
            "Informativa",
            "No se pudieron inferir campos de usuario y contraseña en HTML estático.",
            f"URL: {url} | Inputs detectados: {inputs}",
            "Analizar login con navegador/headless o detectar endpoint API de autenticación."
        )

    findings = []

    for payload in SQLI_AUTH_PAYLOADS:
        data = {
            user_field: payload,
            password_field: payload,
        }

        started = time.time()

        try:
            response = client.post(url, data=data)
        except Exception as exc:
            continue

        elapsed = time.time() - started
        body = response.text or ""

        if response_indicates_sqli(body):
            findings.append(
                f"Payload generó error SQL: {payload} | HTTP {response.status_code} | URL final {response.url}"
            )

        elif response_indicates_possible_login(body, response.url):
            findings.append(
                f"Payload produjo respuesta compatible con autenticación anómala: {payload} | HTTP {response.status_code} | URL final {response.url}"
            )

        elif elapsed >= 1.2 and "sleep" in payload.lower():
            findings.append(
                f"Payload temporal produjo latencia anómala: {payload} | Tiempo {elapsed:.2f}s"
            )

    if findings:
        return build_result(
            "SQLi en login HTML",
            "Posible hallazgo",
            "Alta",
            "Se observaron respuestas compatibles con SQL Injection o bypass lógico en endpoint de autenticación.",
            " | ".join(findings[:5]),
            "Validar manualmente con proxy, revisar consultas parametrizadas, ORM, validación server-side y gestión de errores."
        )

    return build_result(
        "SQLi en login HTML",
        "No evidenciado",
        "Informativa",
        "No se evidenció SQL Injection con payloads comunes sobre campos de login HTML.",
        f"URL: {url} | Payloads probados: {len(SQLI_AUTH_PAYLOADS)}",
        "Complementar con pruebas autenticadas, análisis de API y payloads específicos según tecnología."
    )


def scan_auth_sqli(pages, client):
    results = []

    auth_pages = [page for page in pages or [] if is_auth_page(page)]

    if not auth_pages:
        return [build_result(
            "SQLi en login",
            "No probado",
            "Informativa",
            "No se detectaron rutas de autenticación candidatas.",
            "Sin páginas clasificadas como auth.",
            "Mejorar discovery, análisis JS y detección de endpoints API."
        )]

    for page in auth_pages:
        html_result = test_html_login_sqli(client, page)
        results.append(html_result)

    browser_results = scan_browser_auth_sqli(
        pages=auth_pages,
        max_payloads=None,
        headless=True
    )

    results.extend(browser_results)

    return results