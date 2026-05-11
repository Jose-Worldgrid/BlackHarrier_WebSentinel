from bs4 import BeautifulSoup
from urllib.parse import urljoin


AUTH_KEYWORDS = [
    "login", "signin", "auth", "account", "session", "admin",
    "iniciar-sesion", "inicio-sesion", "iniciar sesión", "acceder", "entrar"
]

REGISTER_KEYWORDS = [
    "register", "signup", "registro", "registrarse", "regístrate",
    "crear-cuenta", "create-account", "crear cuenta"
]

USERNAME_HINTS = [
    "user", "username", "email", "correo", "login", "identifier"
]

PASSWORD_HINTS = [
    "pass", "password", "pwd", "contraseña"
]


def safe_text(value):
    return str(value or "").strip()


def extract_forms_from_html(page_url: str, html: str):
    soup = BeautifulSoup(html or "", "html.parser")
    forms = []

    for index, form in enumerate(soup.find_all("form"), start=1):
        method = (form.get("method") or "GET").upper()
        action = urljoin(page_url, form.get("action") or page_url)

        fields = []

        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name") or field.get("id") or field.get("placeholder") or ""
            field_type = (field.get("type") or field.name or "").lower()

            fields.append({
                "name": name,
                "type": field_type,
                "value": field.get("value") or "",
                "id": field.get("id") or "",
                "placeholder": field.get("placeholder") or "",
                "autocomplete": field.get("autocomplete") or "",
                "aria_label": field.get("aria-label") or ""
            })

        forms.append({
            "page_url": page_url,
            "index": index,
            "method": method,
            "action": action,
            "source": "html_form",
            "fields": fields
        })

    return forms


def extract_loose_inputs(page_url: str, html: str):
    soup = BeautifulSoup(html or "", "html.parser")
    fields = []

    for field in soup.find_all(["input", "textarea", "select"]):
        name = field.get("name") or field.get("id") or field.get("placeholder") or field.get("aria-label") or ""
        field_type = (field.get("type") or field.name or "").lower()

        if not name and field_type not in ["email", "password", "text", "search", "tel"]:
            continue

        fields.append({
            "name": name,
            "type": field_type,
            "value": field.get("value") or "",
            "id": field.get("id") or "",
            "placeholder": field.get("placeholder") or "",
            "autocomplete": field.get("autocomplete") or "",
            "aria_label": field.get("aria-label") or ""
        })

    if not fields:
        return []

    return [{
        "page_url": page_url,
        "index": 1,
        "method": "CLIENT_SIDE",
        "action": "unknown_api_endpoint",
        "source": "loose_inputs",
        "fields": fields
    }]


def extract_links_and_buttons(page_url: str, html: str):
    soup = BeautifulSoup(html or "", "html.parser")
    items = []

    for element in soup.find_all(["a", "button"]):
        text = element.get_text(" ", strip=True)
        href = element.get("href")

        items.append({
            "tag": element.name,
            "text": text,
            "href": urljoin(page_url, href) if href else "",
            "type": element.get("type") or "",
            "aria_label": element.get("aria-label") or ""
        })

    return items


def is_auth_url(url: str):
    value = safe_text(url).lower()
    return any(keyword in value for keyword in AUTH_KEYWORDS)


def is_registration_url(url: str):
    value = safe_text(url).lower()
    return any(keyword in value for keyword in REGISTER_KEYWORDS)


def field_blob(field):
    return " ".join([
        safe_text(field.get("name")),
        safe_text(field.get("type")),
        safe_text(field.get("id")),
        safe_text(field.get("placeholder")),
        safe_text(field.get("autocomplete")),
        safe_text(field.get("aria_label")),
    ]).lower()


def classify_form(form):
    joined = " ".join([
        safe_text(form.get("action")),
        safe_text(form.get("page_url")),
        " ".join([field_blob(field) for field in form.get("fields", [])])
    ]).lower()

    has_password = any(
        field.get("type") == "password"
        or any(hint in field_blob(field) for hint in PASSWORD_HINTS)
        for field in form.get("fields", [])
    )

    has_username = any(
        field.get("type") in ["email", "text"]
        or any(hint in field_blob(field) for hint in USERNAME_HINTS)
        for field in form.get("fields", [])
    )

    if has_password and has_username:
        return "authentication"

    if any(keyword in joined for keyword in REGISTER_KEYWORDS):
        return "registration"

    if any(keyword in joined for keyword in AUTH_KEYWORDS):
        return "authentication_candidate"

    return "generic"


def describe_fields(form):
    fields = form.get("fields", [])

    if not fields:
        return "Sin campos detectados."

    return ", ".join([
        f"{safe_text(field.get('name')) or 'sin_nombre'}:{safe_text(field.get('type')) or 'unknown'}"
        for field in fields
    ])


def detect_client_side_auth_forms(page):
    page_url = page.get("final_url") or page.get("url")
    html = page.get("html", "") or ""
    soup = BeautifulSoup(html, "html.parser")

    inputs = soup.find_all(["input", "textarea", "select"])
    buttons = soup.find_all(["button", "a"])

    input_types = [(field.get("type") or "").lower() for field in inputs]

    input_blobs = [
        " ".join([
            field.get("name") or "",
            field.get("id") or "",
            field.get("placeholder") or "",
            field.get("autocomplete") or "",
            field.get("aria-label") or "",
            field.get("type") or "",
        ]).lower()
        for field in inputs
    ]

    button_texts = [
        " ".join([
            button.get_text(" ", strip=True),
            button.get("aria-label") or "",
            button.get("href") or "",
        ]).lower()
        for button in buttons
    ]

    has_email = (
        "email" in input_types
        or any("email" in blob or "correo" in blob for blob in input_blobs)
    )

    has_password = (
        "password" in input_types
        or any("password" in blob or "contraseña" in blob or "pwd" in blob for blob in input_blobs)
    )

    has_login_button = any(
        marker in text
        for text in button_texts
        for marker in ["iniciar sesión", "login", "sign in", "acceder", "entrar"]
    )

    has_register_link = any(
        marker in text
        for text in button_texts
        for marker in ["regístrate", "registrarse", "registro", "crear cuenta", "signup", "register"]
    )

    if has_email and has_password:
        fields = []

        for field in inputs:
            field_type = (field.get("type") or field.name or "").lower()
            blob = " ".join([
                field.get("name") or "",
                field.get("id") or "",
                field.get("placeholder") or "",
                field.get("autocomplete") or "",
                field.get("aria-label") or "",
                field_type,
            ]).lower()

            if (
                "email" in blob
                or "correo" in blob
                or "password" in blob
                or "contraseña" in blob
                or field_type in ["email", "password", "text"]
            ):
                fields.append({
                    "name": field.get("name") or field.get("id") or field.get("placeholder") or field.get("aria-label") or "",
                    "type": field_type,
                    "value": field.get("value") or "",
                    "id": field.get("id") or "",
                    "placeholder": field.get("placeholder") or "",
                    "autocomplete": field.get("autocomplete") or "",
                    "aria_label": field.get("aria-label") or ""
                })

        return [{
            "page_url": page_url,
            "index": 1,
            "method": "CLIENT_SIDE",
            "action": "unknown_api_endpoint",
            "source": "client_side_auth_form",
            "fields": fields,
            "has_login_button": has_login_button,
            "has_register_link": has_register_link
        }]

    return []


def detect_registration_links(page):
    page_url = page.get("final_url") or page.get("url")
    html = page.get("html", "") or ""
    links = extract_links_and_buttons(page_url, html)
    detected = []

    for item in links:
        blob = " ".join([
            safe_text(item.get("text")),
            safe_text(item.get("href")),
            safe_text(item.get("aria_label")),
        ]).lower()

        if any(keyword in blob for keyword in REGISTER_KEYWORDS):
            detected.append(item)

    return detected


def build_form_result(page, form):
    form_type = classify_form(form)
    method = form.get("method", "")
    fields = describe_fields(form)
    source = form.get("source", "unknown")

    if form_type == "authentication":
        severity = "Media"
        description = (
            "Formulario compatible con autenticación detectado. "
            "Debe revisarse frente a bypass lógico, enumeración de usuarios, rate limiting, CSRF, validación server-side "
            "y manejo de errores."
        )
    elif form_type == "registration":
        severity = "Media"
        description = (
            "Formulario compatible con registro detectado. "
            "Debe revisarse frente a abuso de alta, enumeración, validación de entrada y controles anti-automatización."
        )
    elif form_type == "authentication_candidate":
        severity = "Media"
        description = (
            "Formulario o conjunto de inputs compatible con autenticación candidata detectado. "
            "Puede requerir análisis de JavaScript/API para identificar el endpoint real."
        )
    else:
        severity = "Informativa"
        description = f"Formulario o conjunto de inputs detectado mediante método {method}."

    extra = ""

    if source == "client_side_auth_form":
        extra = (
            " | Tipo de formulario: client-side sin etiqueta <form> clásica"
            f" | Botón login: {form.get('has_login_button')}"
            f" | Enlace registro: {form.get('has_register_link')}"
        )

    return {
        "control": f"Formulario detectado - {form.get('page_url')}",
        "status": "Detectado",
        "severity": severity,
        "description": description,
        "evidence": (
            f"Página: {form.get('page_url')} | "
            f"Action: {form.get('action')} | "
            f"Método: {method} | "
            f"Origen detección: {source} | "
            f"Tipo: {form_type} | "
            f"Campos: {fields}"
            f"{extra}"
        ),
        "recommendation": (
            "Identificar el endpoint real de envío, validar CSRF, sanitización, validación server-side, rate limiting, "
            "gestión de errores y controles de autenticación/autorización."
        )
    }


def build_registration_link_result(page, links):
    page_url = page.get("final_url") or page.get("url")
    evidence = "; ".join([
        f"texto='{safe_text(item.get('text'))}', href='{safe_text(item.get('href'))}'"
        for item in links[:8]
    ])

    return {
        "control": f"Enlace de registro detectado - {page_url}",
        "status": "Detectado",
        "severity": "Informativa",
        "description": (
            "Se detectó un enlace o botón compatible con flujo de registro. "
            "Debe incluirse en el alcance de crawling y pruebas de formularios."
        ),
        "evidence": f"Página: {page_url} | Enlaces/botones: {evidence}",
        "recommendation": (
            "Añadir la ruta de registro al crawling, analizar formulario asociado y revisar validación, abuso de alta "
            "y controles anti-automatización."
        )
    }


def build_client_side_auth_result(page):
    url = page.get("url")
    final_url = page.get("final_url") or url
    classification = page.get("classification", "")
    status_code = page.get("status_code", "")
    html = page.get("html") or ""
    lower = html.lower()

    indicators = []

    for marker in [
        "password", "email", "correo", "login", "signin", "auth", "credentials",
        "registro", "register", "signup", "__next_data__", "fetch(",
        "axios", "signin", "signIn", "iniciar sesión"
    ]:
        if marker.lower() in lower:
            indicators.append(marker)

    if classification == "auth" or is_auth_url(url) or is_auth_url(final_url):
        control = f"Endpoint de autenticación detectado - {url}"
        description = (
            "Ruta compatible con autenticación detectada. No se localizó formulario HTML clásico, "
            "pero existen indicadores de flujo de autenticación client-side o API."
        )
        recommendation = (
            "Analizar bundles JavaScript, identificar endpoints API de autenticación, ejecutar pruebas con navegador/headless "
            "y validar enumeración, bypass lógico, fuerza bruta, CSRF, rate limiting y manejo de errores."
        )
    elif classification == "registration" or is_registration_url(url) or is_registration_url(final_url):
        control = f"Endpoint de registro detectado - {url}"
        description = (
            "Ruta compatible con registro detectada. No se localizó formulario HTML clásico, "
            "pero puede estar renderizada en cliente o usar endpoints API."
        )
        recommendation = (
            "Analizar endpoints de registro, validación server-side, abuso de alta, controles anti-automatización "
            "y manejo de errores."
        )
    else:
        return None

    return {
        "control": control,
        "status": "Detectado",
        "severity": "Media",
        "description": description,
        "evidence": (
            f"URL: {url} | URL final: {final_url} | HTTP: {status_code} | "
            f"Clasificación: {classification} | Indicadores: "
            f"{', '.join(sorted(set(indicators))) if indicators else 'No concluyentes'}"
        ),
        "recommendation": recommendation
    }


def scan_forms_from_pages(pages):
    results = []

    for page in pages:
        requested_url = str(page.get("url") or "").strip().rstrip("/")
        final_url = str(page.get("final_url") or page.get("url") or "").strip().rstrip("/")
        redirected = bool(requested_url and final_url and requested_url != final_url)

        page_url = final_url or requested_url
        html = page.get("html", "") or ""

        browser_runtime = page.get("browser_runtime") or {}
        runtime_inputs = browser_runtime.get("inputs") or []

        # Detectar login dinámico desde runtime REAL
        if runtime_inputs:
            has_password = any("password" in str(f).lower() for f in runtime_inputs)
            has_user = any("email" in str(f).lower() or "user" in str(f).lower() for f in runtime_inputs)

            if has_user and has_password:
                results.append({
                    "control": f"Formulario dinámico detectado (Playwright) - {page_url}",
                    "status": "Detectado",
                    "severity": "Media",
                    "description": "Formulario de autenticación detectado mediante renderizado real en navegador (client-side).",
                    "evidence": f"Inputs detectados: {len(runtime_inputs)} | Tipo: login dinámico",
                    "recommendation": "Identificar endpoint API real y ejecutar pruebas de SQLi/bypass directamente contra backend."
                })

        classic_forms = []
        client_side_auth_forms = []
        loose_input_forms = []

        if not redirected:
            classic_forms = extract_forms_from_html(page_url, html)
            client_side_auth_forms = detect_client_side_auth_forms(page)

            if not classic_forms and not client_side_auth_forms:
                loose_input_forms = extract_loose_inputs(page_url, html)

        forms = classic_forms + client_side_auth_forms + loose_input_forms

        for form in forms:
            results.append(build_form_result(page, form))

        registration_links = detect_registration_links(page)
        if registration_links:
            results.append(build_registration_link_result(page, registration_links))

        if redirected:
            continue

        if not forms:
            fallback = build_client_side_auth_result(page)
            if fallback:
                results.append(fallback)

    if not results:
        results.append({
            "control": "Formularios",
            "status": "No detectado",
            "severity": "Informativa",
            "description": "No se detectaron formularios ni rutas de autenticación/registro en las páginas analizadas.",
            "evidence": "Sin formularios HTML estáticos, inputs sueltos ni endpoints de autenticación clasificados.",
            "recommendation": "Ampliar alcance a rutas autenticadas, analizar JavaScript y ejecutar navegador/headless si aplica."
        })

    return results