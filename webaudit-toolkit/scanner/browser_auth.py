import re
import time
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from scanner.payloads.sqli_payloads import SQLI_AUTH_PAYLOADS


SUCCESS_MARKERS = [
    "dashboard", "panel", "admin", "perfil", "profile", "mi cuenta",
    "account", "logout", "cerrar sesión", "cerrar sesion", "usuario"
]

FAILURE_MARKERS = [
    "credenciales", "incorrect", "incorrecto", "invalid", "denied",
    "unauthorized", "no autorizado", "error", "failed", "fallido"
]

SQL_ERROR_MARKERS = [
    "sql syntax", "mysql", "mariadb", "postgresql", "sqlite", "odbc",
    "jdbc", "sqlstate", "database error", "syntax error",
    "unclosed quotation", "quoted string not properly terminated"
]

AUTH_PATH_MARKERS = [
    "login", "signin", "auth", "iniciar-sesion", "inicio-sesion"
]


def build_result(control, status, severity, description, evidence, recommendation):
    return {
        "control": control,
        "status": status,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def is_auth_page(page):
    url = str(page.get("url") or "").lower()
    final_url = str(page.get("final_url") or "").lower()
    classification = str(page.get("classification") or "").lower()

    return (
        classification == "auth"
        or any(marker in url for marker in AUTH_PATH_MARKERS)
        or any(marker in final_url for marker in AUTH_PATH_MARKERS)
    )


def normalize_url(url):
    return str(url or "").strip()


def same_origin(url_a, url_b):
    a = urlparse(url_a)
    b = urlparse(url_b)
    return a.scheme == b.scheme and a.netloc == b.netloc


def has_marker(text, markers):
    lower = (text or "").lower()
    return any(marker in lower for marker in markers)


def find_login_fields(page):
    password_locator = page.locator(
        "input[type='password'], input[name*='pass' i], input[id*='pass' i], "
        "input[placeholder*='contraseña' i], input[placeholder*='password' i]"
    )

    if password_locator.count() == 0:
        return None, None

    password_input = password_locator.first

    user_locator = page.locator(
        "input[type='email'], input[name*='email' i], input[id*='email' i], "
        "input[placeholder*='email' i], input[placeholder*='correo' i], "
        "input[name*='user' i], input[id*='user' i], input[name*='login' i], "
        "input[type='text']"
    )

    if user_locator.count() == 0:
        return None, password_input

    return user_locator.first, password_input


def click_login(page):
    button_patterns = [
        re.compile("iniciar sesión", re.I),
        re.compile("login", re.I),
        re.compile("sign in", re.I),
        re.compile("acceder", re.I),
        re.compile("entrar", re.I),
    ]

    for pattern in button_patterns:
        locator = page.get_by_role("button", name=pattern)
        if locator.count() > 0:
            locator.first.click(timeout=3000)
            return True

    submit = page.locator("button[type='submit'], input[type='submit']")
    if submit.count() > 0:
        submit.first.click(timeout=3000)
        return True

    page.keyboard.press("Enter")
    return True


def collect_dom_evidence(page):
    try:
        body = page.content()
    except Exception:
        body = ""

    try:
        text = page.locator("body").inner_text(timeout=3000)
    except Exception:
        text = ""

    return body, text


def test_payload_with_browser(login_url, payload, timeout_ms=12000, headless=True):
    network_hits = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1366, "height": 900},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            locale="es-ES",
        )

        page = context.new_page()

        def on_response(response):
            try:
                network_hits.append({
                    "url": response.url,
                    "status": response.status,
                    "content_type": response.headers.get("content-type", "")
                })
            except Exception:
                pass

        page.on("response", on_response)

        try:
            page.goto(login_url, wait_until="networkidle", timeout=timeout_ms)
        except PlaywrightTimeoutError:
            try:
                page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as exc:
                browser.close()
                return {
                    "tested": False,
                    "payload": payload,
                    "reason": f"No se pudo cargar login: {exc}",
                    "initial_url": login_url,
                    "final_url": login_url,
                    "network_hits": network_hits,
                }

        initial_url = page.url

        try:
            page.wait_for_timeout(1200)
            user_input, password_input = find_login_fields(page)

            if not user_input or not password_input:
                body, text = collect_dom_evidence(page)
                browser.close()
                return {
                    "tested": False,
                    "payload": payload,
                    "reason": "No se detectaron campos email/usuario y contraseña en DOM renderizado.",
                    "initial_url": initial_url,
                    "final_url": page.url,
                    "body_sample": text[:500],
                    "network_hits": network_hits,
                }

            user_input.fill(payload, timeout=5000)
            password_input.fill(payload, timeout=5000)

            started = time.time()
            click_login(page)

            try:
                page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except Exception:
                page.wait_for_timeout(2500)

            elapsed = time.time() - started
            final_url = page.url
            body, text = collect_dom_evidence(page)
            combined = f"{final_url}\n{text}\n{body[:8000]}"

            sql_error = has_marker(combined, SQL_ERROR_MARKERS)
            success = has_marker(combined, SUCCESS_MARKERS)
            failure = has_marker(combined, FAILURE_MARKERS)

            url_changed = final_url != initial_url
            left_auth_flow = not any(marker in final_url.lower() for marker in AUTH_PATH_MARKERS)

            possible_bypass = (
                sql_error
                or success
                or (url_changed and left_auth_flow and not failure and same_origin(initial_url, final_url))
                or (elapsed >= 1.2 and "sleep" in payload.lower())
            )

            browser.close()

            return {
                "tested": True,
                "payload": payload,
                "initial_url": initial_url,
                "final_url": final_url,
                "url_changed": url_changed,
                "elapsed": elapsed,
                "sql_error": sql_error,
                "success_marker": success,
                "failure_marker": failure,
                "possible_bypass": possible_bypass,
                "body_sample": text[:700],
                "network_hits": network_hits[-12:],
            }

        except Exception as exc:
            browser.close()
            return {
                "tested": False,
                "payload": payload,
                "reason": str(exc),
                "initial_url": initial_url,
                "final_url": page.url if page else login_url,
                "network_hits": network_hits,
            }


def test_browser_auth_sqli_for_page(page, max_payloads=None, headless=True):
    login_url = normalize_url(page.get("final_url") or page.get("url"))

    payloads = SQLI_AUTH_PAYLOADS
    if max_payloads is not None:
        payloads = payloads[:max_payloads]

    tested = []
    findings = []
    errors = []

    for payload in payloads:
        result = test_payload_with_browser(
            login_url=login_url,
            payload=payload,
            headless=headless,
        )

        if not result.get("tested"):
            errors.append(result)
            continue

        tested.append(result)

        if result.get("possible_bypass"):
            findings.append(result)

    if findings:
        evidence_items = []

        for item in findings[:5]:
            evidence_items.append(
                f"Payload: {item.get('payload')} | "
                f"Inicial: {item.get('initial_url')} | "
                f"Final: {item.get('final_url')} | "
                f"SQL error: {item.get('sql_error')} | "
                f"Success marker: {item.get('success_marker')} | "
                f"Tiempo: {item.get('elapsed'):.2f}s"
            )

        return build_result(
            "SQLi/bypass en login renderizado por navegador",
            "Posible hallazgo",
            "Crítica",
            "Se observaron respuestas compatibles con bypass de autenticación, SQLi o comportamiento anómalo en login renderizado por JavaScript.",
            " || ".join(evidence_items),
            "Validar manualmente con proxy, revisar endpoint API real, consultas parametrizadas, control de sesión, rate limiting y gestión de errores."
        )

    if tested:
        return build_result(
            "SQLi/bypass en login renderizado por navegador",
            "No evidenciado",
            "Informativa",
            "No se evidenció bypass de autenticación ni SQLi usando navegador real sobre el login detectado.",
            f"URL: {login_url} | Payloads probados: {len(tested)} | Errores técnicos: {len(errors)}",
            "Complementar con revisión manual, pruebas autenticadas, análisis de endpoints API y payloads específicos de tecnología."
        )

    return build_result(
        "SQLi/bypass en login renderizado por navegador",
        "No probado",
        "Media",
        "No se pudo ejecutar la prueba con navegador sobre el login detectado.",
        f"URL: {login_url} | Errores: {len(errors)} | Ejemplo: {errors[0].get('reason') if errors else 'sin detalle'}",
        "Verificar Playwright, selectores del formulario, bloqueos del navegador y renderizado client-side."
    )


def scan_browser_auth_sqli(pages, max_payloads=None, headless=True):
    auth_pages = [page for page in pages or [] if is_auth_page(page)]

    if not auth_pages:
        return [build_result(
            "SQLi/bypass en login renderizado por navegador",
            "No probado",
            "Informativa",
            "No se detectaron rutas de autenticación candidatas para navegador.",
            "Sin páginas clasificadas como auth/login/signin.",
            "Mejorar discovery, analizar rutas embebidas en JavaScript y ampliar diccionario."
        )]

    results = []

    for page in auth_pages:
        results.append(test_browser_auth_sqli_for_page(
            page=page,
            max_payloads=max_payloads,
            headless=headless,
        ))

    return results