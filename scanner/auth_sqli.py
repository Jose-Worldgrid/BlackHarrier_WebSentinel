from scanner.browser_auth import scan_browser_auth_sqli


def build_result(control, status, severity, description, evidence, recommendation):
    return {
        "control": control,
        "status": status,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def is_auth_candidate(page):
    values = " ".join([
        str(page.get("classification", "")),
        str(page.get("url", "")),
        str(page.get("final_url", "")),
        str(page.get("ai_context", {}).get("page_type", "")),
    ]).lower()

    markers = [
        "auth",
        "login",
        "signin",
        "iniciar-sesion",
        "inicio-sesion",
        "session",
    ]

    return any(marker in values for marker in markers)


def has_auth_form_indicators(page):
    forms_blob = str(page.get("forms") or "").lower()
    runtime_blob = str((page.get("browser_runtime") or {}).get("inputs") or page.get("browser_inputs") or "").lower()
    combined = f"{forms_blob} {runtime_blob}"

    has_password = "password" in combined or "contraseña" in combined
    has_user = any(token in combined for token in ["email", "correo", "usuario", "user", "login"])
    return has_password and has_user


def build_auth_candidates(pages):
    auth_pages = []
    seen = set()

    for page in pages or []:
        url = str(page.get("final_url") or page.get("url") or "")
        lower_url = url.lower()
        ai_context = page.get("ai_context") or {}
        endpoint_hints = ai_context.get("candidate_endpoints") or []

        is_candidate = (
            is_auth_candidate(page)
            or has_auth_form_indicators(page)
            or any(x in lower_url for x in ["login", "signin", "auth", "session", "token"])
            or bool(endpoint_hints)
        )

        if not is_candidate:
            continue

        page_obj = dict(page)
        page_obj.setdefault("classification", "auth")
        page_obj.setdefault("url", url)
        page_obj.setdefault("final_url", url)

        key = page_obj.get("final_url") or page_obj.get("url")
        if key and key not in seen:
            seen.add(key)
            auth_pages.append(page_obj)

    return auth_pages


def scan_auth_sqli(
    pages,
    client=None,
    max_payloads=None,
    headless=True,
    progress_callback=None
):
    auth_pages = build_auth_candidates(pages)

    if not auth_pages:
        return [build_result(
            "SQLi/bypass en autenticación",
            "No probado",
            "Informativa",
            "No se detectaron rutas de autenticación candidatas.",
            "Sin páginas clasificadas como auth/login/signin.",
            "Mejorar discovery, análisis JavaScript, Playwright runtime y detección de endpoints API."
        )]

    return scan_browser_auth_sqli(
        pages=auth_pages,
        max_payloads=max_payloads,
        headless=headless,
        progress_callback=progress_callback
    )