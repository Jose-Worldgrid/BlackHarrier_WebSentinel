from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from scanner.http_client import HttpClient

USERNAME_HINTS = ["user", "username", "email", "login", "usuario", "correo", "identifier", "mail"]
PASSWORD_HINTS = ["pass", "password", "pwd", "contraseña", "passwd", "clave"]

# Markers indicating a successful login (broad coverage across ES/EN apps)
SUCCESS_MARKERS = [
    "logout", "log out", "log-out", "sign out", "sign-out",
    "cerrar sesión", "cerrar sesion", "salir", "desconectar",
    "dashboard", "panel de", "mi cuenta", "my account", "mi perfil",
    "bienvenido", "bienvenida", "welcome", "your profile", "your account",
    "perfil", "cuenta", "ajustes", "settings", "profile",
    "restaurant dashboard", "user dashboard", "admin panel",
    "gestión", "gestion", "control panel", "backend",
]

# Markers indicating a failed login
FAILURE_MARKERS = [
    "incorrect", "invalid", "wrong", "failed", "failure",
    "credenciales incorrectas", "credenciales inválidas", "usuario no encontrado",
    "contraseña incorrecta", "error de autenticación", "acceso denegado",
    "unauthorized", "not authorized", "denied", "forbidden",
    "invalid credentials", "login failed", "authentication failed",
]

PROTECTED_PATH_HINTS = (
    "admin",
    "dashboard",
    "backoffice",
    "private",
    "account",
    "profile",
    "settings",
    "usuario",
    "perfil",
    "cuenta",
    "panel",
    "manage",
    "internal",
)


def _looks_like_protected_post_request(url: str) -> bool:
    parsed = urlparse(str(url or ""))
    path = (parsed.path or "").lower()
    if not path:
        return False
    return any(f"/{hint}" in path for hint in PROTECTED_PATH_HINTS)


def _sync_browser_cookies_into_client(client, cookies):
    """Copy Playwright cookies into requests session for post-login scans."""
    for cookie in cookies or []:
        try:
            name = cookie.get("name")
            value = cookie.get("value")
            domain = cookie.get("domain")
            path = cookie.get("path") or "/"
            if not name:
                continue
            client.session.cookies.set(name=name, value=value or "", domain=domain, path=path)
        except Exception:
            continue


def _authenticate_dynamic_login(client, login_url, username, password):
    """Fallback authentication for SPA/client-side login pages without classic HTML forms."""
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
        from scanner.browser_auth import find_login_fields, click_login, collect_dom_evidence
    except Exception as exc:
        return {
            "status": "Indeterminado",
            "severity": "Baja",
            "description": "No se pudo activar fallback de login dinámico (Playwright no disponible).",
            "evidence": f"{type(exc).__name__}: {exc}",
            "final_url": login_url,
            "http_status": 0,
            "cookies_loaded": 0,
        }

    # Keep only strong post-login markers; avoid weak terms that appear in public nav.
    success_markers = [
        "logout",
        "log out",
        "close session",
        "sign out",
        "cerrar sesión",
        "cerrar sesion",
        "signout",
        "my account",
        "welcome back",
    ]
    failed_markers = [
        "invalid credentials",
        "login failed",
        "authentication failed",
        "wrong password",
        "incorrect password",
        "incorrect username",
        "credenciales incorrectas",
        "credenciales inválidas",
        "contraseña incorrecta",
        "usuario no encontrado",
        "acceso denegado",
        "iniciar sesión fallido",
    ]

    browser = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()

            network_posts = []

            def _on_request(req):
                try:
                    if req.method == "POST":
                        network_posts.append(str(req.url or ""))
                except Exception:
                    pass

            page.on("request", _on_request)

            try:
                page.goto(login_url, wait_until="networkidle", timeout=12000)
            except PlaywrightTimeoutError:
                page.goto(login_url, wait_until="domcontentloaded", timeout=12000)

            user_input, password_input = find_login_fields(page)
            if not user_input or not password_input:
                html_body, body_text = collect_dom_evidence(page)
                lower = (html_body + "\n" + body_text).lower()
                status = "Fallido" if any(x in lower for x in failed_markers) else "Indeterminado"
                description = (
                    "No se localizaron campos de login renderizados en navegador."
                    if status == "Indeterminado"
                    else "El flujo parece rechazar autenticación en login dinámico."
                )
                return {
                    "status": status,
                    "severity": "Baja" if status == "Indeterminado" else "Media",
                    "description": description,
                    "evidence": f"Login dinámico sin campos detectados en {login_url}",
                    "final_url": page.url,
                    "http_status": 0,
                    "cookies_loaded": 0,
                }

            user_input.fill(username, timeout=5000)
            password_input.fill(password, timeout=5000)
            click_login(page, password_input=password_input)
            page.wait_for_timeout(2500)

            try:
                page.wait_for_load_state("networkidle", timeout=9000)
            except Exception:
                pass

            html_body, body_text = collect_dom_evidence(page)
            lower = (html_body + "\n" + body_text).lower()
            final_url = page.url

            cookies = context.cookies()
            _sync_browser_cookies_into_client(client, cookies)
            cookie_count = len(cookies)

            cookie_names = [str(c.get("name") or "").lower() for c in cookies]
            benign_cookie_hints = ("locale", "lang", "consent", "analytics", "ga", "gid", "utm")
            auth_cookie_hints = (
                "session", "token", "auth", "jwt", "sid", "user", "logged", "next-auth", "woocommerce"
            )
            has_auth_cookie = any(
                any(h in name for h in auth_cookie_hints) and not any(b in name for b in benign_cookie_hints)
                for name in cookie_names
            )

            has_success_marker = any(x in lower for x in success_markers)
            has_fail_marker = any(x in lower for x in failed_markers)
            moved_from_login = str(final_url or "").strip().rstrip("/") != str(login_url).strip().rstrip("/")
            final_path = urlparse(final_url).path.lower()
            final_is_login_like = any(tok in final_path for tok in ("login", "signin", "auth", "session"))

            has_protected_posts = any(_looks_like_protected_post_request(u) for u in network_posts)

            if not has_auth_cookie and not has_protected_posts and final_is_login_like and not has_fail_marker:
                # Retry once in-place: some SPA flows need a second submit trigger.
                try:
                    click_login(page, password_input=password_input)
                except Exception:
                    try:
                        page.keyboard.press("Enter")
                    except Exception:
                        pass
                page.wait_for_timeout(2200)
                try:
                    page.wait_for_load_state("networkidle", timeout=7000)
                except Exception:
                    pass

                html_body, body_text = collect_dom_evidence(page)
                lower = (html_body + "\n" + body_text).lower()
                final_url = page.url
                cookies = context.cookies()
                _sync_browser_cookies_into_client(client, cookies)
                cookie_count = len(cookies)
                cookie_names = [str(c.get("name") or "").lower() for c in cookies]
                has_auth_cookie = any(
                    any(h in name for h in auth_cookie_hints) and not any(b in name for b in benign_cookie_hints)
                    for name in cookie_names
                )
                has_success_marker = any(x in lower for x in success_markers)
                has_fail_marker = any(x in lower for x in failed_markers)
                moved_from_login = str(final_url or "").strip().rstrip("/") != str(login_url).strip().rstrip("/")
                final_path = urlparse(final_url).path.lower()
                final_is_login_like = any(tok in final_path for tok in ("login", "signin", "auth", "session"))
                has_protected_posts = any(_looks_like_protected_post_request(u) for u in network_posts)

            # Success requires robust evidence: redirect away from login or explicit auth cookies.
            if (moved_from_login and not final_is_login_like and not has_fail_marker) or has_auth_cookie or has_protected_posts:
                status = "Autenticado"
                severity = "Informativa"
                description = "Inicio de sesión dinámico aparentemente correcto (Playwright fallback)."
            elif has_fail_marker:
                status = "Fallido"
                severity = "Media"
                description = "El inicio de sesión dinámico parece haber fallado."
            elif has_success_marker:
                status = "Indeterminado"
                severity = "Baja"
                description = "Se detectaron marcadores de posible sesión, pero sin evidencia robusta de autenticación."
            else:
                status = "Indeterminado"
                severity = "Baja"
                description = "No se pudo confirmar de forma concluyente el estado de login dinámico."

            return {
                "status": status,
                "severity": severity,
                "description": description,
                "evidence": (
                    f"Login dinámico: {login_url} | Final URL: {final_url} | "
                    f"Cookies cargadas: {cookie_count} | Auth cookies: {'sí' if has_auth_cookie else 'no'} | "
                    f"POST protegidos: {'sí' if has_protected_posts else 'no'}"
                ),
                "final_url": final_url,
                "http_status": 0,
                "cookies_loaded": cookie_count,
            }
    except Exception as exc:
        return {
            "status": "Indeterminado",
            "severity": "Baja",
            "description": "Error durante fallback de login dinámico.",
            "evidence": f"{type(exc).__name__}: {exc}",
            "final_url": login_url,
            "http_status": 0,
            "cookies_loaded": 0,
        }
    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                pass


def authenticate(login_url: str, username: str, password: str, verify_ssl: bool = True):
    client = HttpClient(verify_ssl=verify_ssl)

    if not username or not password:
        return client, [{
            "control": "Autenticación",
            "status": "No configurado",
            "severity": "Informativa",
            "description": "No se introdujeron credenciales.",
            "evidence": "Escaneo ejecutado sin sesión autenticada.",
            "recommendation": "Introducir credenciales para ampliar cobertura post-login."
        }]

    results = []

    try:
        response = client.get(login_url)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            # No HTML forms — SPA/dynamic login: use Playwright
            fallback = _authenticate_dynamic_login(client, login_url, username, password)
            return client, [{
                "control": "Autenticación",
                "status": fallback.get("status", "Indeterminado"),
                "severity": fallback.get("severity", "Baja"),
                "description": fallback.get("description", "Login dinámico procesado."),
                "evidence": fallback.get("evidence", login_url),
                "login_url": login_url,
                "final_url": fallback.get("final_url", login_url),
                "http_status": fallback.get("http_status", 0),
                "recommendation": "Validar sesión post-login con ruta protegida y cookies sincronizadas."
            }]

        # Classic HTML form login
        form = forms[0]
        action = urljoin(login_url, form.get("action") or login_url)
        method = (form.get("method") or "POST").upper()

        # Build payload from form fields
        data = {}
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue
            lower = name.lower()
            value = field.get("value") or ""

            if any(h in lower for h in USERNAME_HINTS):
                data[name] = username
            elif any(h in lower for h in PASSWORD_HINTS):
                data[name] = password
            elif field.get("type", "").lower() not in ("submit", "button", "reset", "image"):
                data[name] = value  # preserve hidden tokens (CSRF, etc.)

        if method == "POST":
            login_response = client.post(action, data=data)
        else:
            login_response = client.get(action, params=data)

        body = login_response.text.lower()
        final_url = str(login_response.url or "")
        status_code = int(getattr(login_response, "status_code", 0) or 0)

        # Detect success via: markers OR redirect away from login URL
        login_base = urlparse(login_url).path.rstrip("/")
        final_base = urlparse(final_url).path.rstrip("/")
        redirected_away = bool(final_base and final_base != login_base and "login" not in final_base)

        # Check for auth session cookies
        auth_cookies = [
            c for c in client.session.cookies
            if any(tok in str(c.name or "").lower() for tok in
                   ("session", "token", "auth", "jwt", "sid", "user"))
        ]

        has_success = any(m in body for m in SUCCESS_MARKERS)
        has_failure = any(m in body for m in FAILURE_MARKERS)

        if has_success or (redirected_away and not has_failure) or len(auth_cookies) > 0:
            status = "Autenticado"
            severity = "Informativa"
            description = "Inicio de sesión aparentemente correcto."
            if auth_cookies:
                description += f" Cookies de sesión detectadas: {', '.join(c.name for c in auth_cookies[:4])}."
        elif has_failure:
            status = "Fallido"
            severity = "Media"
            description = "Las credenciales fueron rechazadas por el servidor."
        else:
            status = "Indeterminado"
            severity = "Baja"
            description = "No se pudo confirmar el estado de autenticación. Sin marcadores claros."

        results.append({
            "control": "Autenticación",
            "status": status,
            "severity": severity,
            "description": description,
            "evidence": (
                f"POST → {action} | HTTP {status_code} | "
                f"Final URL: {final_url} | "
                f"Cookies auth: {len(auth_cookies)} | "
                f"Redirigió: {'sí' if redirected_away else 'no'}"
            ),
            "login_url": login_url,
            "final_url": final_url,
            "http_status": status_code,
            "recommendation": "Verificar manualmente con herramienta de proxy (Burp/ZAP) si el estado es Indeterminado."
        })

    except Exception as exc:
        # If TLS trust chain fails, retry once with SSL verification disabled.
        if verify_ssl and "CERTIFICATE_VERIFY_FAILED" in str(exc).upper():
            retry_client, retry_results = authenticate(
                login_url,
                username,
                password,
                verify_ssl=False,
            )
            for row in retry_results:
                row["evidence"] = f"{row.get('evidence', '')} | SSL fallback: verify_ssl=False"
            return retry_client, retry_results

        results.append({
            "control": "Autenticación",
            "status": "Error",
            "severity": "Media",
            "description": "Error técnico durante el intento de autenticación.",
            "evidence": str(exc),
            "recommendation": "Revisar URL de login, credenciales y accesibilidad del endpoint."
        })

    return client, results