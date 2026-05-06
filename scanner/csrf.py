from scanner.forms import extract_forms_from_html


CSRF_KEYWORDS = ["csrf", "_csrf", "token", "authenticity_token", "__requestverificationtoken"]
HEADER_BASED_CSRF_HINTS = [
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "xsrf-token",
]
META_CSRF_NAMES = ["csrf-token", "csrf_token", "xsrf-token", "_csrf"]


def build_field_blob(field):
    return " ".join([
        str(field.get("name", "")),
        str(field.get("id", "")),
        str(field.get("placeholder", "")),
        str(field.get("aria_label", "")),
        str(field.get("type", "")),
    ]).lower()


def has_meta_csrf_hint(html):
    lower = (html or "").lower()
    return any(
        f'name="{name}"' in lower or f"name='{name}'" in lower
        for name in META_CSRF_NAMES
    )


def has_header_based_csrf_hint(html):
    lower = (html or "").lower()
    return any(marker in lower for marker in HEADER_BASED_CSRF_HINTS)


def scan_csrf_from_pages(pages):
    results = []

    for page in pages:
        page_html = page.get("html", "") or ""
        meta_hint = has_meta_csrf_hint(page_html)
        header_hint = has_header_based_csrf_hint(page_html)
        forms = extract_forms_from_html(page["url"], page["html"])

        for form in forms:
            if form["method"] != "POST":
                continue

            field_names = [str(f.get("name", "")).lower() for f in form["fields"]]
            has_hidden_token = any(
                (f.get("type", "")).lower() == "hidden"
                and any(keyword in build_field_blob(f) for keyword in CSRF_KEYWORDS)
                for f in form["fields"]
            )
            has_any_token_like_field = any(
                any(keyword in build_field_blob(f) for keyword in CSRF_KEYWORDS)
                for f in form["fields"]
            )

            if has_hidden_token:
                results.append({
                    "control": f"Protección CSRF - formulario {form['index']}",
                    "status": "Correcto",
                    "severity": "Informativa",
                    "description": "Se detectó un token anti-CSRF oculto en el formulario POST.",
                    "evidence": f"Página: {page['url']} | Action: {form['action']} | Campos: {', '.join(field_names)}",
                    "recommendation": "Validar que el token sea único por sesión/petición y se verifique server-side."
                })
            elif has_any_token_like_field or meta_hint:
                results.append({
                    "control": f"Protección CSRF - formulario {form['index']}",
                    "status": "Comprobado",
                    "severity": "Baja",
                    "description": "Se detectaron indicios de protección CSRF, pero no evidencia concluyente de validación efectiva.",
                    "evidence": (
                        f"Página: {page['url']} | Action: {form['action']} | "
                        f"Campos: {', '.join(field_names)} | Meta CSRF: {meta_hint}"
                    ),
                    "recommendation": "Confirmar validación server-side del token y revisar SameSite/Origin/Referer."
                })
            elif header_hint:
                results.append({
                    "control": f"Protección CSRF - formulario {form['index']}",
                    "status": "Posible hallazgo",
                    "severity": "Media",
                    "description": "No se observó token en formulario POST, aunque la página sugiere protección CSRF basada en cabeceras.",
                    "evidence": f"Página: {page['url']} | Action: {form['action']} | Campos: {', '.join(field_names)}",
                    "recommendation": "Verificar si el backend exige cabecera anti-CSRF y bloquea envíos sin token/cabecera válida."
                })
            else:
                results.append({
                    "control": f"Protección CSRF - formulario {form['index']}",
                    "status": "Hallazgo",
                    "severity": "Alta",
                    "description": "Formulario POST sin token anti-CSRF evidente.",
                    "evidence": f"Página: {page['url']} | Action: {form['action']} | Campos: {', '.join(field_names)}",
                    "recommendation": "Implementar tokens anti-CSRF únicos por sesión y validar Origin/Referer cuando aplique."
                })

    if not results:
        results.append({
            "control": "Protección CSRF",
            "status": "No probado",
            "severity": "Informativa",
            "description": "No se detectaron formularios POST en el alcance analizado.",
            "evidence": "Sin formularios POST.",
            "recommendation": "Ampliar el análisis a rutas autenticadas."
        })

    return results