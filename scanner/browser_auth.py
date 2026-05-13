import asyncio
import json
import logging
import re
import sys
import time
from urllib.parse import parse_qsl, urlencode
from urllib.parse import urlparse

import requests
import urllib3
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from scanner.payloads.sqli_payloads import SQLI_AUTH_PAYLOADS
from scanner.http_client import get_default_proxy_url


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

if sys.platform.startswith("win"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        logger.debug("No se pudo configurar WindowsProactorEventLoopPolicy", exc_info=True)


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

AUTH_ENDPOINT_MARKERS = [
    "login", "signin", "auth", "session", "usuario", "user", "account", "api"
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


def normalize_url(url):
    return str(url or "").strip()


def get_requests_proxy_config():
    proxy_url = get_default_proxy_url()
    if not proxy_url:
        return None
    return {
        "http": proxy_url,
        "https": proxy_url,
    }


def get_playwright_proxy_config():
    proxy_url = get_default_proxy_url()
    if not proxy_url:
        return None
    return {"server": proxy_url}


def same_origin(url_a, url_b):
    a = urlparse(url_a)
    b = urlparse(url_b)
    return a.scheme == b.scheme and a.netloc == b.netloc


def has_marker(text, markers):
    lower = str(text or "").lower()
    return any(marker in lower for marker in markers)


def is_auth_page(page):
    url = str(page.get("url") or "").lower()
    final_url = str(page.get("final_url") or "").lower()
    classification = str(page.get("classification") or "").lower()

    ai_context = page.get("ai_context") or {}
    ai_page_type = str(ai_context.get("page_type") or "").lower()

    return (
        classification == "auth"
        or ai_page_type == "auth"
        or any(marker in url for marker in AUTH_PATH_MARKERS)
        or any(marker in final_url for marker in AUTH_PATH_MARKERS)
    )


def is_auth_endpoint(url):
    lower = str(url or "").lower()
    return any(marker in lower for marker in AUTH_ENDPOINT_MARKERS)


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

    buttons = page.locator("button")
    if buttons.count() > 0:
        buttons.first.click(timeout=3000)
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


def extract_auth_runtime_evidence(login_url, timeout_ms=7000, headless=True):
    network_events = []
    browser = None

    try:
        with sync_playwright() as p:
            launch_kwargs = {"headless": headless}
            proxy_cfg = get_playwright_proxy_config()
            if proxy_cfg:
                launch_kwargs["proxy"] = proxy_cfg
            browser = p.chromium.launch(**launch_kwargs)
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1366, "height": 900},
                locale="es-ES",
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
            )

            page = context.new_page()

            def on_request(request):
                try:
                    if request.method in ["POST", "PUT", "PATCH"]:
                        network_events.append({
                            "type": "request",
                            "method": request.method,
                            "url": request.url,
                            "post_data": request.post_data or "",
                            "headers": dict(request.headers),
                        })
                except Exception:
                    logger.debug("Error capturando evento request en Playwright", exc_info=True)

            def on_response(response):
                try:
                    url = response.url
                    if is_auth_endpoint(url):
                        network_events.append({
                            "type": "response",
                            "url": url,
                            "status": response.status,
                            "headers": dict(response.headers),
                        })
                except Exception:
                    logger.debug("Error capturando evento response en Playwright", exc_info=True)

            page.on("request", on_request)
            page.on("response", on_response)

            try:
                page.goto(login_url, wait_until="networkidle", timeout=timeout_ms)
            except PlaywrightTimeoutError:
                page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)

            page.wait_for_timeout(400)

            inputs = page.locator("input, textarea, select").evaluate_all("""
                els => els.map((el, index) => ({
                    index,
                    tag: el.tagName.toLowerCase(),
                    type: el.getAttribute("type") || "",
                    name: el.getAttribute("name") || "",
                    id: el.getAttribute("id") || "",
                    placeholder: el.getAttribute("placeholder") || "",
                    autocomplete: el.getAttribute("autocomplete") || "",
                    aria_label: el.getAttribute("aria-label") || ""
                }))
            """)

            buttons = page.locator("button, a").evaluate_all("""
                els => els.map((el, index) => ({
                    index,
                    tag: el.tagName.toLowerCase(),
                    text: (el.innerText || el.textContent || "").trim(),
                    href: el.getAttribute("href") || "",
                    type: el.getAttribute("type") || "",
                    aria_label: el.getAttribute("aria-label") || ""
                }))
            """)

            user_input, password_input = find_login_fields(page)
            submitted = False

            if user_input and password_input:
                user_input.fill("blackharrier_probe@example.com", timeout=5000)
                password_input.fill("BlackHarrierProbe123!", timeout=5000)
                click_login(page)
                submitted = True
                page.wait_for_timeout(2500)

            html = page.content()
            final_url = page.url
            title = page.title()

            browser.close()
            browser = None

            candidate_endpoints = []
            for event in network_events:
                url = event.get("url", "")
                if is_auth_endpoint(url):
                    candidate_endpoints.append(url)

            return {
                "ok": True,
                "url": login_url,
                "final_url": final_url,
                "title": title,
                "submitted_probe": submitted,
                "inputs": inputs,
                "buttons": buttons,
                "network_events": network_events,
                "candidate_endpoints": sorted(set(candidate_endpoints)),
                "html": html,
                "error": "",
            }

    except Exception as exc:
        if browser:
            try:
                browser.close()
            except Exception:
                logger.debug("Error cerrando navegador tras fallo en extract_auth_runtime_evidence", exc_info=True)

        return {
            "ok": False,
            "url": login_url,
            "final_url": login_url,
            "title": "",
            "submitted_probe": False,
            "inputs": [],
            "buttons": [],
            "network_events": network_events,
            "candidate_endpoints": [],
            "html": "",
            "error": f"{type(exc).__name__}: {exc}",
        }


def build_json_payloads(payload):
    return [
        {"email": payload, "password": payload},
        {"username": payload, "password": payload},
        {"user": payload, "password": payload},
        {"identifier": payload, "password": payload},
        {"login": payload, "password": payload},
        {"email": payload, "password": "test"},
        {"email": "admin@example.com", "password": payload},
        {"username": "admin", "password": payload},
    ]


def build_form_payloads(payload):
    return [
        {"email": payload, "password": payload},
        {"username": payload, "password": payload},
        {"user": payload, "password": payload},
        {"identifier": payload, "password": payload},
        {"login": payload, "password": payload},
        {"email": payload, "password": "test"},
        {"email": "admin@example.com", "password": payload},
        {"username": "admin", "password": payload},
    ]


def analyze_direct_response(endpoint, payload, response, mode):
    text = response.text or ""
    lower = text.lower()

    sql_error = has_marker(lower, SQL_ERROR_MARKERS)
    success = has_marker(lower, SUCCESS_MARKERS)
    failure = has_marker(lower, FAILURE_MARKERS)

    # Avoid false positives: success markers alone are not enough unless the response moved away from the endpoint.
    url_changed = response.url != endpoint
    possible_bypass = sql_error or (success and not failure and url_changed and response.status_code < 400)

    return {
        "tested": True,
        "mode": mode,
        "endpoint": endpoint,
        "payload": payload,
        "status_code": response.status_code,
        "final_url": response.url,
        "sql_error": sql_error,
        "success_marker": success,
        "failure_marker": failure,
        "possible_bypass": possible_bypass,
        "body_sample": text[:700],
    }


def mutate_json_payload(raw_data, payload):
    try:
        body = json.loads(raw_data or "{}")
    except Exception:
        return raw_data

    if not isinstance(body, dict):
        return raw_data

    for key in list(body.keys()):
        lower = str(key).lower()
        if any(token in lower for token in ["email", "user", "username", "login", "identifier", "pass", "password"]):
            body[key] = payload

    try:
        return json.dumps(body)
    except Exception:
        return raw_data


def mutate_form_payload(raw_data, payload):
    pairs = parse_qsl(raw_data or "", keep_blank_values=True)
    if not pairs:
        return raw_data

    mutated = []
    for key, value in pairs:
        lower = str(key).lower()
        if any(token in lower for token in ["email", "user", "username", "login", "identifier", "pass", "password"]):
            mutated.append((key, payload))
        else:
            mutated.append((key, value))

    try:
        return urlencode(mutated, doseq=True)
    except Exception:
        return raw_data


def mutate_request_body(post_data, content_type, payload):
    content_type = str(content_type or "").lower()

    if "application/json" in content_type:
        return mutate_json_payload(post_data, payload)

    if "application/x-www-form-urlencoded" in content_type:
        return mutate_form_payload(post_data, payload)

    return post_data


def test_payload_direct_api(endpoint, payload, timeout=5):
    attempts = []
    proxy_cfg = get_requests_proxy_config()

    for data in build_json_payloads(payload):
        try:
            response = requests.post(
                endpoint,
                json=data,
                timeout=timeout,
                verify=False,
                proxies=proxy_cfg,
                allow_redirects=True,
                headers={
                    "User-Agent": "BlackHarrier-WebSentinel/1.0",
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json",
                },
            )
            attempts.append(analyze_direct_response(endpoint, payload, response, "json"))
        except Exception as exc:
            attempts.append({
                "tested": False,
                "mode": "json",
                "endpoint": endpoint,
                "payload": payload,
                "error": f"{type(exc).__name__}: {exc}",
            })

    for data in build_form_payloads(payload):
        try:
            response = requests.post(
                endpoint,
                data=data,
                timeout=timeout,
                verify=False,
                proxies=proxy_cfg,
                allow_redirects=True,
                headers={
                    "User-Agent": "BlackHarrier-WebSentinel/1.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            attempts.append(analyze_direct_response(endpoint, payload, response, "form"))
        except Exception as exc:
            attempts.append({
                "tested": False,
                "mode": "form",
                "endpoint": endpoint,
                "payload": payload,
                "error": f"{type(exc).__name__}: {exc}",
            })

    for item in attempts:
        if item.get("possible_bypass"):
            return item

    tested = [x for x in attempts if x.get("tested")]
    if tested:
        return tested[0]

    return attempts[0] if attempts else {
        "tested": False,
        "endpoint": endpoint,
        "payload": payload,
        "error": "Sin intentos ejecutados."
    }


def test_payload_with_browser(login_url, payload, timeout_ms=3500, headless=True):
    network_hits = []
    browser = None

    try:
        with sync_playwright() as p:
            launch_kwargs = {"headless": headless}
            proxy_cfg = get_playwright_proxy_config()
            if proxy_cfg:
                launch_kwargs["proxy"] = proxy_cfg
            browser = p.chromium.launch(**launch_kwargs)
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
                    logger.debug("Error registrando respuesta de red en browser_dom", exc_info=True)

            page.on("response", on_response)

            try:
                page.goto(login_url, wait_until="networkidle", timeout=timeout_ms)
            except PlaywrightTimeoutError:
                page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)

            initial_url = page.url
            page.wait_for_timeout(350)

            user_input, password_input = find_login_fields(page)

            if not user_input or not password_input:
                body, text = collect_dom_evidence(page)
                browser.close()
                browser = None

                return {
                    "tested": False,
                    "payload": payload,
                    "reason": "No se detectaron campos email/usuario y contraseña en DOM renderizado.",
                    "initial_url": initial_url,
                    "final_url": initial_url,
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
                page.wait_for_timeout(900)

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
                or (success and not failure and url_changed and left_auth_flow and same_origin(initial_url, final_url))
                or (elapsed >= 1.2 and "sleep" in payload.lower())
            )

            browser.close()
            browser = None

            return {
                "tested": True,
                "mode": "browser_dom",
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
        if browser:
            try:
                browser.close()
            except Exception:
                logger.debug("Error cerrando navegador tras fallo en test_payload_with_browser_dom", exc_info=True)

        return {
            "tested": False,
            "mode": "browser_dom",
            "payload": payload,
            "reason": f"{type(exc).__name__}: {exc}",
            "initial_url": login_url,
            "final_url": login_url,
            "network_hits": network_hits,
        }


def test_payload_with_browser_intercept(login_url, payload, timeout_ms=3500, headless=True):
    network_hits = []
    browser = None
    intercepted = {"count": 0}

    try:
        with sync_playwright() as p:
            launch_kwargs = {"headless": headless}
            proxy_cfg = get_playwright_proxy_config()
            if proxy_cfg:
                launch_kwargs["proxy"] = proxy_cfg
            browser = p.chromium.launch(**launch_kwargs)
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

            def route_handler(route, request):
                try:
                    should_try = request.method in ["POST", "PUT", "PATCH"] and is_auth_endpoint(request.url)
                    if not should_try:
                        route.continue_()
                        return

                    headers = dict(request.headers)
                    original_data = request.post_data or ""
                    content_type = headers.get("content-type", "")
                    mutated_data = mutate_request_body(original_data, content_type, payload)

                    if mutated_data != original_data:
                        intercepted["count"] += 1
                        route.continue_(post_data=mutated_data, headers=headers)
                        return

                    route.continue_()
                except Exception:
                    route.continue_()
                    logger.debug("Error en route handler de Playwright intercept", exc_info=True)

            context.route("**/*", route_handler)

            page = context.new_page()

            def on_response(response):
                try:
                    network_hits.append({
                        "url": response.url,
                        "status": response.status,
                        "content_type": response.headers.get("content-type", "")
                    })
                except Exception:
                    logger.debug("Error registrando respuesta de red en browser_intercept", exc_info=True)

            page.on("response", on_response)

            try:
                page.goto(login_url, wait_until="networkidle", timeout=timeout_ms)
            except PlaywrightTimeoutError:
                page.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)

            initial_url = page.url
            page.wait_for_timeout(350)

            user_input, password_input = find_login_fields(page)

            if not user_input or not password_input:
                body, text = collect_dom_evidence(page)
                browser.close()
                browser = None

                return {
                    "tested": False,
                    "mode": "browser_intercept",
                    "payload": payload,
                    "reason": "No se detectaron campos email/usuario y contraseña en DOM renderizado.",
                    "initial_url": initial_url,
                    "final_url": initial_url,
                    "body_sample": text[:500],
                    "network_hits": network_hits,
                }

            user_input.fill("probe.user@example.com", timeout=5000)
            password_input.fill("NotThePayload123!", timeout=5000)

            started = time.time()
            click_login(page)

            try:
                page.wait_for_load_state("networkidle", timeout=timeout_ms)
            except Exception:
                page.wait_for_timeout(900)

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
                or (success and not failure and url_changed and left_auth_flow and same_origin(initial_url, final_url))
                or (elapsed >= 1.2 and "sleep" in payload.lower())
            )

            browser.close()
            browser = None

            return {
                "tested": intercepted["count"] > 0,
                "mode": "browser_intercept",
                "payload": payload,
                "initial_url": initial_url,
                "final_url": final_url,
                "url_changed": url_changed,
                "elapsed": elapsed,
                "sql_error": sql_error,
                "success_marker": success,
                "failure_marker": failure,
                "possible_bypass": possible_bypass,
                "intercepted_requests": intercepted["count"],
                "body_sample": text[:700],
                "network_hits": network_hits[-12:],
                "reason": "No se interceptaron requests auth mutables." if intercepted["count"] == 0 else "",
            }

    except Exception as exc:
        if browser:
            try:
                browser.close()
            except Exception:
                logger.debug("Error cerrando navegador tras fallo en test_payload_with_browser_intercept", exc_info=True)

        return {
            "tested": False,
            "mode": "browser_intercept",
            "payload": payload,
            "reason": f"{type(exc).__name__}: {exc}",
            "initial_url": login_url,
            "final_url": login_url,
            "network_hits": network_hits,
        }


def get_candidate_endpoints_from_page(page):
    runtime = page.get("browser_runtime") or {}
    ai_context = page.get("ai_context") or {}

    endpoints = []

    endpoints.extend(runtime.get("candidate_endpoints") or [])
    endpoints.extend(ai_context.get("candidate_endpoints") or [])

    clean = []
    base_url = page.get("final_url") or page.get("url") or ""

    for endpoint in endpoints:
        endpoint = normalize_url(endpoint)

        if not endpoint:
            continue

        if base_url and not same_origin(base_url, endpoint):
            continue

        if endpoint not in clean:
            clean.append(endpoint)

    return clean


def test_browser_auth_sqli_for_page(page, max_payloads=None, headless=True, progress_callback=None):
    login_url = normalize_url(page.get("final_url") or page.get("url"))
    candidate_endpoints = get_candidate_endpoints_from_page(page)

    payloads = SQLI_AUTH_PAYLOADS
    if max_payloads is not None:
        payloads = payloads[:max_payloads]

    total_payloads = len(payloads)
    tested = []
    findings = []
    errors = []

    for index, payload in enumerate(payloads, start=1):

        if candidate_endpoints:
            for endpoint in candidate_endpoints:
                if progress_callback:
                    progress_callback({
                        "phase": "SQL Injection en autenticación",
                        "technique": "Bypass SQLi contra endpoint API",
                        "current": index,
                        "total": total_payloads,
                        "payload": payload,
                        "login_url": login_url,
                        "target": endpoint,
                        "candidate_endpoints": [endpoint],
                        "field": "email",
                        "mode": "api",
                        "detail": "Probando payload contra endpoint de autenticación capturado.",
                    })

                result = test_payload_direct_api(endpoint, payload)

                if not result.get("tested"):
                    errors.append(result)
                    continue

                tested.append(result)

                if result.get("possible_bypass"):
                    findings.append(result)

        else:
            if progress_callback:
                progress_callback({
                    "phase": "SQL Injection en autenticación",
                    "technique": "Bypass SQLi sobre login renderizado",
                    "current": index,
                    "total": total_payloads,
                    "payload": payload,
                    "login_url": login_url,
                    "target": login_url,
                    "candidate_endpoints": [],
                    "field": "email",
                    "mode": "browser_dom",
                    "detail": "Probando payload en formulario de login renderizado.",
                })

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

            if progress_callback:
                progress_callback({
                    "phase": "SQL Injection en autenticación",
                    "technique": "Intercepción activa de request auth (tipo proxy)",
                    "current": index,
                    "total": total_payloads,
                    "payload": payload,
                    "login_url": login_url,
                    "target": login_url,
                    "candidate_endpoints": [],
                    "field": "email/password",
                    "mode": "browser_intercept",
                    "detail": "Interceptando y mutando body de petición auth en vuelo.",
                })

            intercept_result = test_payload_with_browser_intercept(
                login_url=login_url,
                payload=payload,
                headless=headless,
            )

            if not intercept_result.get("tested"):
                errors.append(intercept_result)
            else:
                tested.append(intercept_result)
                if intercept_result.get("possible_bypass"):
                    findings.append(intercept_result)

    if findings:
        evidence_items = []

        for item in findings[:5]:
            evidence_items.append(
                f"Modo: {item.get('mode', '')} | "
                f"Endpoint/URL: {item.get('endpoint') or item.get('initial_url') or login_url} | "
                f"Payload: {item.get('payload')} | "
                f"HTTP: {item.get('status_code', '')} | "
                f"Final: {item.get('final_url', '')} | "
                f"SQL error: {item.get('sql_error')} | "
                f"Success marker: {item.get('success_marker')}"
            )

        return build_result(
            "SQLi/bypass en autenticación",
            "Posible hallazgo",
            "Crítica",
            "Se observaron respuestas compatibles con bypass de autenticación, SQLi o comportamiento anómalo.",
            " || ".join(evidence_items),
            "Validar manualmente con proxy, revisar endpoint API real, consultas parametrizadas, control de sesión, rate limiting y gestión de errores."
        )

    if tested:
        tested_payloads = [str(item.get("payload", "")) for item in tested[:10]]

        target_info = (
            f"Endpoints candidatos: {candidate_endpoints}"
            if candidate_endpoints
            else f"Login DOM: {login_url}"
        )

        return build_result(
            "SQLi/bypass en autenticación",
            "No evidenciado",
            "Informativa",
            "No se evidenció bypass de autenticación ni SQLi con los payloads configurados.",
            (
                f"{target_info} | "
                f"Payloads configurados: {len(payloads)} | "
                f"Intentos ejecutados: {len(tested)} | "
                f"Errores técnicos: {len(errors)} | "
                f"Payloads probados: {tested_payloads}"
            ),
            "Complementar con revisión manual, análisis de endpoint API real, pruebas autenticadas y payloads específicos de tecnología."
        )

    return build_result(
        "SQLi/bypass en autenticación",
        "No probado",
        "Media",
        "No se pudo ejecutar la prueba sobre el login detectado.",
        (
            f"URL: {login_url} | "
            f"Endpoints candidatos: {candidate_endpoints} | "
            f"Errores: {len(errors)} | "
            f"Ejemplo: {errors[0].get('reason') or errors[0].get('error') if errors else 'sin detalle'}"
        ),
        "Verificar Playwright, versión de Python, selectores del formulario, endpoints capturados y bloqueos del navegador."
    )


def scan_browser_auth_sqli(pages, max_payloads=None, headless=True, progress_callback=None):
    auth_pages = [page for page in pages or [] if is_auth_page(page)]

    if not auth_pages:
        return [build_result(
            "SQLi/bypass en autenticación",
            "No probado",
            "Informativa",
            "No se detectaron rutas de autenticación candidatas.",
            "Sin páginas clasificadas como auth/login/signin.",
            "Mejorar discovery, analizar rutas embebidas en JavaScript y ampliar diccionario."
        )]

    results = []

    for page in auth_pages:
        results.append(test_browser_auth_sqli_for_page(
            page=page,
            max_payloads=max_payloads,
            headless=headless,
            progress_callback=progress_callback,
        ))

    return results