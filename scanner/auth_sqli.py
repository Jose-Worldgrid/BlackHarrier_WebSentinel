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


def scan_auth_sqli(
    pages,
    client=None,
    max_payloads=None,
    headless=True,
    progress_callback=None
):
    auth_pages = [
        page for page in pages or []
        if is_auth_candidate(page)
    ]

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