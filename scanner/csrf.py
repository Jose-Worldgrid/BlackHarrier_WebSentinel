from scanner.forms import extract_forms_from_html


CSRF_KEYWORDS = ["csrf", "_csrf", "token", "authenticity_token", "__requestverificationtoken"]


def scan_csrf_from_pages(pages):
    results = []

    for page in pages:
        forms = extract_forms_from_html(page["url"], page["html"])

        for form in forms:
            if form["method"] != "POST":
                continue

            field_names = [f["name"].lower() for f in form["fields"]]
            has_token = any(any(keyword in name for keyword in CSRF_KEYWORDS) for name in field_names)

            if not has_token:
                results.append({
                    "control": f"Protección CSRF - formulario {form['index']}",
                    "status": "Hallazgo",
                    "severity": "Alta",
                    "description": "Formulario POST sin token anti-CSRF evidente.",
                    "evidence": f"Página: {page['url']} | Action: {form['action']} | Campos: {', '.join(field_names)}",
                    "recommendation": "Implementar tokens anti-CSRF únicos por sesión y validar Origin/Referer cuando aplique."
                })
            else:
                results.append({
                    "control": f"Protección CSRF - formulario {form['index']}",
                    "status": "Correcto",
                    "severity": "Informativa",
                    "description": "Se detectó un campo compatible con token anti-CSRF.",
                    "evidence": f"Página: {page['url']} | Campos: {', '.join(field_names)}",
                    "recommendation": "Validar que el token sea único, impredecible y verificado en servidor."
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