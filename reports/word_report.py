from collections import Counter, defaultdict
from datetime import datetime
import os

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.shared import Inches, Pt, RGBColor


# ── Colour palette ───────────────────────────────────────────────────
SEV_BG = {
    "Crítica":    "7B0000",   # dark red
    "Alta":       "C0392B",   # red
    "Media":      "D35400",   # orange
    "Baja":       "2E86C1",   # blue
    "Informativa":"616A6B",   # grey
}
SEV_FG = {
    "Crítica":    "FFFFFF",
    "Alta":       "FFFFFF",
    "Media":      "FFFFFF",
    "Baja":       "FFFFFF",
    "Informativa":"FFFFFF",
}
HEADER_BG = "1C2833"   # dark slate
HEADER_FG = "F2F3F4"


def _set_cell_bg(cell, hex_color):
    """Fill a table cell background with a hex colour (no #)."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def _set_cell_font(cell, hex_color, bold=False, size_pt=None):
    for para in cell.paragraphs:
        for run in para.runs:
            r = int(hex_color[0:2], 16)
            g = int(hex_color[2:4], 16)
            b = int(hex_color[4:6], 16)
            run.font.color.rgb = RGBColor(r, g, b)
            if bold:
                run.font.bold = True
            if size_pt:
                run.font.size = Pt(size_pt)


def style_header_row(row, bg=HEADER_BG, fg=HEADER_FG):
    """Apply dark header style to all cells in a row."""
    for cell in row.cells:
        _set_cell_bg(cell, bg)
        for para in cell.paragraphs:
            for run in para.runs:
                r = int(fg[0:2], 16)
                g = int(fg[2:4], 16)
                b = int(fg[4:6], 16)
                run.font.color.rgb = RGBColor(r, g, b)
                run.font.bold = True


def style_severity_cell(cell, severity):
    bg = SEV_BG.get(severity, "616A6B")
    fg = SEV_FG.get(severity, "FFFFFF")
    _set_cell_bg(cell, bg)
    _set_cell_font(cell, fg, bold=True)


SEVERITY_ORDER = {
    "Crítica": 1,
    "Alta": 2,
    "Media": 3,
    "Baja": 4,
    "Informativa": 5,
}

FINDING_STATUSES = {
    "Hallazgo",
    "Posible hallazgo",
}

ERROR_STATUSES = {
    "Error",
}

OK_STATUSES = {
    "Correcto",
    "Detectado",
    "No evidenciado",
    "No detectado",
}

OFFENSIVE_MODULES = {
    "XSS reflejado",
    "SQL Injection",
    "SQL Injection Auth (Browser)",
    "Open Redirect",
    "XSS DOM",
    "SSTI",
    "SSRF",
    "Path Traversal",
}

REPORTABLE_PAGE_CLASSES = {
    "auth",
    "registration",
    "protected",
    "protected_redirect_to_auth",
    "admin_candidate",
    "api_candidate",
    "sensitive_candidate",
    "server_error",
    "error_disclosure_candidate",
}


def safe_text(value):
    return str(value if value is not None else "")


def truncate(text, limit=450):
    text = safe_text(text)
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def is_finding(item):
    return item.get("Resultado") in FINDING_STATUSES


def is_error(item):
    return item.get("Resultado") in ERROR_STATUSES


def is_ok(item):
    return item.get("Resultado") in OK_STATUSES


def is_reportable_page(page):
    status = safe_text(page.get("status_code"))
    classification = safe_text(page.get("classification"))

    if status == "404":
        return False

    if classification in ["soft_404", "request_error", "html_candidate"]:
        return False

    if classification in REPORTABLE_PAGE_CLASSES:
        return True

    if status.startswith("5"):
        return True

    return False


def get_form_detection_summary(page):
    forms = page.get("forms") or []
    browser_runtime = page.get("browser_runtime") or {}
    inputs = browser_runtime.get("inputs") or page.get("browser_inputs") or []
    buttons = browser_runtime.get("buttons") or page.get("browser_buttons") or []

    has_runtime_auth_form = any(
        "password" in str(field).lower() or "contraseña" in str(field).lower()
        for field in inputs
    ) and any(
        "email" in str(field).lower()
        or "correo" in str(field).lower()
        or "user" in str(field).lower()
        or "usuario" in str(field).lower()
        or "login" in str(field).lower()
        for field in inputs
    )

    has_browser_form = any(
        isinstance(form, dict)
        and (
            str(form.get("source", "")) == "browser_runtime"
            or str(form.get("type", "")) == "client_side_auth_form"
            or str(form.get("method", "")).lower() == "client-side/js"
        )
        for form in forms
    )

    html_forms = [
        form for form in forms
        if not (
            isinstance(form, dict)
            and (
                str(form.get("source", "")) == "browser_runtime"
                or str(form.get("type", "")) == "client_side_auth_form"
                or str(form.get("method", "")).lower() == "client-side/js"
            )
        )
    ]

    if has_runtime_auth_form or has_browser_form:
        form_type = "Formulario dinámico detectado con Playwright"
    elif html_forms:
        form_type = "Formulario HTML clásico"
    elif inputs:
        form_type = "Inputs renderizados sin clasificar"
    else:
        form_type = "No detectado"

    return {
        "forms_count": max(len(forms), 1 if (has_runtime_auth_form or has_browser_form) else 0),
        "form_type": form_type,
        "inputs_count": len(inputs),
        "buttons_count": len(buttons),
        "has_runtime_auth_form": has_runtime_auth_form,
        "has_browser_form": has_browser_form,
        "has_html_form": bool(html_forms),
    }


def get_page_observation(page):
    classification = safe_text(page.get("classification", "sin clasificar"))
    form_summary = get_form_detection_summary(page)
    forms_count = form_summary["forms_count"]

    if classification in ["auth", "registration"]:
        if forms_count:
            return f"Ruta compatible con autenticación/registro. {form_summary['form_type']}."
        return "Ruta compatible con autenticación/registro sin formulario renderizado; revisar JavaScript y endpoints API."

    if classification == "protected_redirect_to_auth":
        return "Ruta sensible que redirige a autenticación. Revisar control de acceso tras login."

    if classification == "protected":
        return "Ruta protegida detectada. Revisar autorización y exposición."

    if classification == "admin_candidate":
        if forms_count:
            return (
                f"Ruta administrativa candidata. Redirige o carga formulario de autenticación ({form_summary['form_type']}). "
                "El formulario puede pertenecer a la página de destino del redirect, no al propio recurso administrativo."
            )
        return "Ruta administrativa candidata a revisión de control de acceso."

    if classification == "api_candidate":
        return "Ruta candidata a API; revisar métodos, autenticación y errores."

    if classification == "sensitive_candidate":
        return "Ruta sensible candidata; revisar exposición de secretos, backups o configuración."

    if classification == "server_error":
        return "Error 5xx detectado; revisar filtrado de información técnica."

    if classification == "error_disclosure_candidate":
        return "Respuesta con indicadores de error técnico o posible disclosure."

    return "Elemento relevante identificado para revisión manual."


def sort_results(results):
    return sorted(
        results,
        key=lambda r: (
            SEVERITY_ORDER.get(r.get("Severidad", ""), 99),
            r.get("Módulo", ""),
            r.get("Control", ""),
        ),
    )


def set_document_style(document):
    styles = document.styles

    normal = styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(9)

    for style_name in ["Heading 1", "Heading 2", "Heading 3"]:
        style = styles[style_name]
        style.font.name = "Arial"
        style.font.bold = True


def add_logo(document):
    logo_path = "Logo_horizontal.png"

    if os.path.exists(logo_path):
        paragraph = document.add_paragraph()
        paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run = paragraph.add_run()
        run.add_picture(logo_path, width=Inches(1.65))


def add_title_page(document, audit_name, target_url, scan_mode=None, pages_count=None):
    add_logo(document)

    title = document.add_heading(
        "INFORME TÉCNICO DE AUDITORÍA DE SEGURIDAD WEB - BLACKHARRIER WEB SENTINEL",
        0,
    )
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    document.add_paragraph("")
    document.add_paragraph(f"Proyecto: {audit_name}")
    document.add_paragraph(f"Objetivo evaluado: {target_url}")

    if scan_mode:
        document.add_paragraph(f"Modo de auditoría: {scan_mode}")

    if pages_count is not None:
        document.add_paragraph(f"URLs HTML analizadas por crawler: {pages_count}")

    document.add_paragraph(f"Fecha de generación: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    document.add_paragraph("Clasificación: Uso interno / Auditoría autorizada")


def add_summary_table(document, findings, errors, oks):
    table = document.add_table(rows=1, cols=2)
    table.style = "Table Grid"

    table.rows[0].cells[0].text = "Indicador"
    table.rows[0].cells[1].text = "Cantidad"

    rows = [
        ("Hallazgos", len(findings)),
        ("Errores de ejecución", len(errors)),
        ("Comprobaciones sin hallazgo / informativas", len(oks)),
    ]

    for name, count in rows:
        row = table.add_row().cells
        row[0].text = name
        row[1].text = str(count)


def add_severity_table(document, findings):
    document.add_heading("Resumen por severidad de hallazgos", 2)

    counts = Counter([x.get("Severidad", "Sin clasificar") for x in findings])

    table = document.add_table(rows=1, cols=2)
    table.style = "Table Grid"

    hdr = table.rows[0]
    hdr.cells[0].text = "Severidad"
    hdr.cells[1].text = "Hallazgos"
    style_header_row(hdr)

    for sev in ["Crítica", "Alta", "Media", "Baja", "Informativa"]:
        row = table.add_row().cells
        row[0].text = sev
        row[1].text = str(counts.get(sev, 0))
        style_severity_cell(row[0], sev)


def add_discovered_surface(document, pages):
    document.add_heading("2. Superficie relevante descubierta por crawler/discovery", 1)

    pages = pages or []
    reportable_pages = [page for page in pages if is_reportable_page(page)]

    if not reportable_pages:
        document.add_paragraph(
            "No se identificaron URLs relevantes reportables. "
            "Las rutas inexistentes, 404, soft-404 y páginas genéricas se han omitido para reducir ruido."
        )
        return

    document.add_paragraph(
        "La siguiente tabla recoge únicamente URLs relevantes para auditoría: autenticación, registro, APIs, "
        "rutas protegidas, rutas administrativas candidatas, errores de servidor o posibles exposiciones sensibles."
    )

    table = document.add_table(rows=1, cols=6)
    table.style = "Table Grid"

    headers = ["URL origen", "URL final", "HTTP", "Clasificación", "Formularios", "Observación"]
    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h

    for page in reportable_pages[:50]:
        url = safe_text(page.get("url"))
        final_url = safe_text(page.get("final_url") or url)
        status_code = safe_text(page.get("status_code"))
        classification = safe_text(page.get("classification", "sin clasificar"))
        form_summary = get_form_detection_summary(page)
        forms_count = form_summary["forms_count"]
        observation = get_page_observation(page)

        row = table.add_row().cells
        row[0].text = truncate(url, 120)
        row[1].text = truncate(final_url, 120)
        row[2].text = status_code
        row[3].text = classification
        row[4].text = str(forms_count)
        row[5].text = truncate(observation, 220)


def add_auth_surface_summary(document, pages):
    auth_keywords = [
        "login",
        "signin",
        "auth",
        "registro",
        "register",
        "signup",
        "iniciar-sesion",
        "inicio-sesion",
        "crear-cuenta",
    ]

    auth_pages = [
        page for page in pages or []
        if is_reportable_page(page)
        and (
            page.get("classification") in ["auth", "registration", "protected_redirect_to_auth"]
            or any(x in safe_text(page.get("url")).lower() for x in auth_keywords)
            or any(x in safe_text(page.get("final_url")).lower() for x in auth_keywords)
        )
    ]

    document.add_heading("3. Superficie de autenticación y registro", 1)

    if not auth_pages:
        document.add_paragraph(
            "No se identificaron rutas válidas de autenticación o registro en el alcance reportable."
        )
        return

    document.add_paragraph(
        "Se identificaron rutas compatibles con autenticación o registro. Estas rutas deben considerarse objetivos "
        "prioritarios para pruebas de validación de entrada, control de errores, rate limiting, enumeración de usuarios, "
        "bypass lógico, SQL Injection controlada y pruebas autenticadas."
    )

    for page in auth_pages[:20]:
        url = page.get("url")
        final_url = page.get("final_url") or url
        form_summary = get_form_detection_summary(page)

        document.add_paragraph(
            f"Ruta detectada: {url} | URL final: {final_url} | HTTP: {page.get('status_code')} | "
            f"Clasificación: {page.get('classification')} | "
            f"Tipo formulario: {form_summary['form_type']} | "
            f"Formularios detectados: {form_summary['forms_count']} | "
            f"Inputs renderizados: {form_summary['inputs_count']} | Botones/enlaces: {form_summary['buttons_count']}",
            style="List Bullet",
        )


def add_top_findings_table(document, findings):
    document.add_heading("4. Hallazgos prioritarios", 1)

    if not findings:
        document.add_paragraph("No se identificaron hallazgos prioritarios en el alcance automatizado.")
        return

    table = document.add_table(rows=1, cols=5)
    table.style = "Table Grid"

    headers = ["Sev.", "Categoría", "Control", "Evidencia resumida", "Recomendación"]
    hdr_row = table.rows[0]
    for i, h in enumerate(headers):
        hdr_row.cells[i].text = h
    style_header_row(hdr_row)

    for item in sort_results(findings)[:25]:
        row = table.add_row().cells
        sev = item.get("Severidad", "")
        row[0].text = sev
        row[1].text = item.get("Módulo", "")
        row[2].text = truncate(item.get("Control", ""), 90)
        row[3].text = truncate(item.get("Evidencia", ""), 220)
        row[4].text = truncate(item.get("Recomendación", ""), 220)
        style_severity_cell(row[0], sev)


def add_execution_errors_table(document, errors):
    document.add_heading("5. Errores o limitaciones de ejecución", 1)

    if not errors:
        document.add_paragraph("No se registraron errores de ejecución en los módulos automatizados.")
        return

    document.add_paragraph(
        "Los siguientes controles no pudieron completarse correctamente. "
        "Estos errores no deben interpretarse como ausencia de vulnerabilidad."
    )

    table = document.add_table(rows=1, cols=4)
    table.style = "Table Grid"

    headers = ["Módulo", "Control", "Descripción", "Evidencia"]

    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h

    for item in errors[:30]:
        row = table.add_row().cells
        row[0].text = truncate(item.get("Módulo", ""), 80)
        row[1].text = truncate(item.get("Control", ""), 100)
        row[2].text = truncate(item.get("Descripción", ""), 220)
        row[3].text = truncate(item.get("Evidencia", ""), 260)


def add_cases_checked(document, results):
    document.add_heading("6. Casos comprobados", 1)

    document.add_paragraph(
        "La siguiente tabla resume los controles evaluados, diferenciando hallazgos, errores y comprobaciones sin evidencia."
    )

    grouped = defaultdict(list)

    for item in results:
        grouped[item.get("Módulo", "Sin módulo")].append(item)

    table = document.add_table(rows=1, cols=6)
    table.style = "Table Grid"

    headers = ["Categoría", "Comprobaciones", "Total", "Hallazgos", "Errores", "Resultado general"]

    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h

    for module, items in grouped.items():
        findings = [x for x in items if is_finding(x)]
        errors = [x for x in items if is_error(x)]

        if findings:
            general = "Requiere revisión"
        elif errors:
            general = "Ejecución incompleta"
        else:
            general = "Sin hallazgos evidenciados"

        examples = [item.get("Control", "") for item in items[:4]]

        row = table.add_row().cells
        row[0].text = module
        row[1].text = truncate("; ".join(examples), 260)
        row[2].text = str(len(items))
        row[3].text = str(len(findings))
        row[4].text = str(len(errors))
        row[5].text = general


def add_test_path_summary(document, pages=None, pages_count=None):
    document.add_heading("7. Trazabilidad resumida de pruebas ejecutadas", 1)

    statements = []

    if pages_count is not None:
        statements.append(
            f"El crawler identificó {pages_count} URL(s) HTML dentro del dominio objetivo."
        )

    auth_pages = [
        page for page in pages or []
        if is_reportable_page(page)
        and page.get("classification") in ["auth", "registration", "protected_redirect_to_auth"]
    ]

    if auth_pages:
        for page in auth_pages[:10]:
            form_summary = get_form_detection_summary(page)
            forms_count = form_summary["forms_count"]
            statements.append(
                f"Durante discovery se identificó la ruta {page.get('url')} "
                f"clasificada como {page.get('classification')}, con código HTTP {page.get('status_code')} "
                f"y {forms_count} formulario(s) detectado(s) ({form_summary['form_type']})."
            )

            if forms_count == 0:
                statements.append(
                    "Al no detectarse formulario renderizado, se considera probable que el flujo de autenticación "
                    "esté renderizado en cliente o use endpoints API. Se recomienda análisis de JavaScript, "
                    "interceptación con navegador/headless y pruebas autenticadas."
                )

    statements.extend([
        "Se evaluaron cabeceras de seguridad HTTP como HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy y Permissions-Policy.",
        "Se analizaron cookies para identificar ausencia de atributos Secure, HttpOnly y SameSite.",
        "Se revisaron configuración CORS, métodos HTTP, exposición de APIs, JWT embebidos y estado TLS/HTTPS.",
        "Se comprobaron rutas comunes de recursos sensibles y directorios expuestos.",
        "Se analizaron formularios, parámetros y rutas descubiertas en el alcance del crawler.",
        "Las pruebas automatizadas se ejecutaron de forma no destructiva y los hallazgos deben validarse manualmente antes de considerarse explotabilidad confirmada.",
    ])

    for statement in statements:
        document.add_paragraph(statement, style="List Bullet")


def infer_payload_families(text):
    value = safe_text(text).lower()
    families = []

    rules = [
        ("XSS script/event", ["<script", "onerror", "onload", "svg", "javascript:"]),
        ("SQLi boolean/error", ["or 1=1", "boolean", "sql", "syntax", "error-based"]),
        ("SQLi time-based", ["sleep(", "benchmark(", "waitfor delay", "time-based"]),
        ("SQLi union", ["union select", "union-based"]),
        ("SSTI expression", ["{{", "${", "<%=", "{%", "template"]),
        ("Open redirect", ["redirect", "next=", "url=", "return=", "//"]),
        ("DOM source/sink", ["document.location", "innerhtml", "eval(", "sink", "source"]),
        ("SSRF internal/metadata", ["169.254.169.254", "localhost", "127.0.0.1", "file://", "gopher://"]),
        ("Path traversal", ["../", "..\\", "%2e%2e%2f", "/etc/passwd", "win.ini"]),
    ]

    for family, markers in rules:
        if any(marker in value for marker in markers):
            families.append(family)

    return families


def summarize_module_status(items):
    statuses = {safe_text(x.get("Resultado")) for x in items}
    if any(status in FINDING_STATUSES for status in statuses):
        return "Con hallazgo"
    if any(status in {"Error", "No probado"} for status in statuses):
        return "Cobertura incompleta"
    return "Ejecutadas sin explotación"


def add_offensive_coverage_section(document, results):
    document.add_heading("8. Pruebas ofensivas superadas y cobertura", 1)

    offensive_items = [
        item for item in results
        if item.get("Módulo") in OFFENSIVE_MODULES
    ]

    if not offensive_items:
        document.add_paragraph(
            "No hay evidencia suficiente de ejecución de pruebas ofensivas en este informe."
        )
        return

    document.add_paragraph(
        "Esta sección resume la cobertura ofensiva ejecutada por módulo, "
        "incluyendo técnicas comprobadas, familias de payloads observadas en evidencias y resultado final de cada batería. "
        "Cuando el estado es 'No evidenciado/No detectado', significa que la prueba se ejecutó y no se consiguió explotación."
    )

    grouped = defaultdict(list)
    for item in offensive_items:
        grouped[item.get("Módulo", "Sin módulo")].append(item)

    table = document.add_table(rows=1, cols=6)
    table.style = "Table Grid"

    headers = [
        "Módulo ofensivo",
        "Total pruebas",
        "Con hallazgo",
        "Estado",
        "Técnicas/controles",
        "Familias de payloads",
    ]
    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h

    for module in sorted(grouped.keys()):
        items = grouped[module]
        findings = [x for x in items if x.get("Resultado") in FINDING_STATUSES]

        techniques = []
        families = []

        for item in items:
            control = truncate(item.get("Control", ""), 80)
            if control and control not in techniques:
                techniques.append(control)

            haystack = " ".join([
                safe_text(item.get("Control")),
                safe_text(item.get("Descripción")),
                safe_text(item.get("Evidencia")),
            ])
            for family in infer_payload_families(haystack):
                if family not in families:
                    families.append(family)

        row = table.add_row().cells
        row[0].text = module
        row[1].text = str(len(items))
        row[2].text = str(len(findings))
        row[3].text = summarize_module_status(items)
        row[4].text = truncate("; ".join(techniques), 260)
        row[5].text = truncate("; ".join(families) if families else "No identificable en evidencia", 220)

    passed_controls = [
        item for item in offensive_items
        if item.get("Resultado") in {"No evidenciado", "No detectado", "Correcto", "Detectado"}
    ]

    document.add_paragraph("Controles ofensivos superados sin evidencia de bypass:")
    if not passed_controls:
        document.add_paragraph("No hay controles superados documentables en esta ejecución.", style="List Bullet")
    else:
        for item in passed_controls[:40]:
            document.add_paragraph(
                f"{item.get('Módulo', '')} | {item.get('Control', '')} | Resultado: {item.get('Resultado', '')}",
                style="List Bullet",
            )


def add_detailed_findings(document, findings):
    document.add_heading("9. Detalle técnico de hallazgos", 1)

    if not findings:
        document.add_paragraph("No se identificaron hallazgos técnicos relevantes.")
        return

    for item in sort_results(findings):
        sev = item.get("Severidad", "Informativa")
        bg = SEV_BG.get(sev, "616A6B")
        fg = SEV_FG.get(sev, "FFFFFF")

        heading = document.add_heading(
            f"{sev} | {item.get('Módulo', '')} | {item.get('Control', '')}",
            2,
        )
        # Colour the heading text to match severity
        for run in heading.runs:
            r_int = int(bg[0:2], 16)
            g_int = int(bg[2:4], 16)
            b_int = int(bg[4:6], 16)
            run.font.color.rgb = RGBColor(r_int, g_int, b_int)
            run.font.bold = True

        document.add_paragraph(f"Resultado: {item.get('Resultado', '')}")
        document.add_paragraph(f"Descripción: {truncate(item.get('Descripción', ''), 900)}")
        document.add_paragraph(f"Evidencia: {truncate(item.get('Evidencia', ''), 900)}")
        document.add_paragraph(f"Recomendación: {truncate(item.get('Recomendación', ''), 900)}")


def add_discovery_dictionary_section(document, discovery):
    document.add_heading("Discovery activo mediante diccionario", 1)

    if not discovery:
        document.add_paragraph("No se proporcionaron resultados de discovery activo.")
        return

    discovered = discovery.get("discovered", [])
    metrics = discovery.get("metrics", {})

    document.add_paragraph(
        "Se ejecutó una fase de descubrimiento activo mediante diccionario de rutas comunes. "
        "El informe omite rutas inexistentes, soft-404 y ruido operativo, manteniendo únicamente rutas con valor técnico."
    )

    document.add_paragraph(f"URLs procesadas: {metrics.get('total_discovered', len(discovered))}")
    document.add_paragraph(f"Rutas relevantes reportables: {metrics.get('reportable_discovered', 0)}")
    document.add_paragraph(f"Rutas de autenticación: {metrics.get('auth_routes', 0)}")
    document.add_paragraph(f"Rutas de registro: {metrics.get('registration_routes', 0)}")
    document.add_paragraph(f"Rutas protegidas/redirigidas: {metrics.get('protected_routes', 0)}")
    document.add_paragraph(f"APIs candidatas: {metrics.get('api_candidates', 0)}")
    document.add_paragraph(f"Rutas sensibles candidatas: {metrics.get('sensitive_candidates', 0)}")
    document.add_paragraph(f"Soft-404 omitidos del informe: {metrics.get('soft_404', 0)}")

    reportable = [
        item for item in discovered
        if item.get("classification") in REPORTABLE_PAGE_CLASSES
        and str(item.get("status_code")) != "404"
    ]

    if not reportable:
        document.add_paragraph(
            "No se identificaron rutas relevantes mediante diccionario. "
            "Las rutas inexistentes o soft-404 se han omitido del informe para reducir ruido."
        )
        return

    table = document.add_table(rows=1, cols=6)
    table.style = "Table Grid"

    headers = ["Origen", "URL solicitada", "URL final", "HTTP", "Clasificación", "Observación"]

    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h

    for item in reportable[:40]:
        row = table.add_row().cells
        row[0].text = str(item.get("source", ""))
        row[1].text = truncate(item.get("requested_url", ""), 120)
        row[2].text = truncate(item.get("final_url", ""), 120)
        row[3].text = str(item.get("status_code", ""))
        row[4].text = str(item.get("classification", ""))
        row[5].text = truncate(item.get("observation", ""), 180)


def add_conclusion(document, findings, errors, results=None):
    document.add_heading("10. Conclusión y próximos pasos", 1)

    offensive_assurance = None
    for item in results or []:
        if item.get("Módulo") == "Aseguramiento ofensivo":
            offensive_assurance = item
            break

    if findings:
        document.add_paragraph(
            "La auditoría automatizada ha identificado hallazgos que requieren revisión técnica. "
            "Se recomienda priorizar los clasificados como críticos o altos y validar manualmente su explotabilidad."
        )
    elif errors:
        document.add_paragraph(
            "No se han identificado hallazgos confirmados, pero existen errores o limitaciones de ejecución en algunos módulos. "
            "La ausencia de hallazgos no debe interpretarse como ausencia de vulnerabilidades."
        )
    else:
        document.add_paragraph(
            "No se han identificado hallazgos relevantes en el alcance automatizado. "
            "Se recomienda complementar con pruebas manuales autenticadas y revisión de lógica de negocio."
        )

    if offensive_assurance:
        document.add_paragraph(
            "Estado de aseguramiento ofensivo: "
            f"{offensive_assurance.get('Resultado', '')}. "
            f"{offensive_assurance.get('Descripción', '')}"
        )

    document.add_paragraph("Plan recomendado:")
    document.add_paragraph("Validar manualmente cualquier hallazgo crítico o alto.", style="List Number")
    document.add_paragraph("Resolver errores de ejecución, bloqueos o limitaciones técnicas.", style="List Number")
    document.add_paragraph("Reejecutar la auditoría tras corregir limitaciones.", style="List Number")
    document.add_paragraph("Ampliar la auditoría con credenciales, navegador/headless y roles de usuario si aplica.", style="List Number")


def generate_word_report(
    audit_name: str,
    target_url: str,
    results: list,
    pages: list | None = None,
    discovery: dict | None = None,
    pages_count: int | None = None,
    scan_mode: str | None = None,
):
    os.makedirs("generated_reports", exist_ok=True)

    pages = pages or []
    if pages_count is None:
        pages_count = len(pages)

    document = Document()
    set_document_style(document)

    section = document.sections[0]
    section.orientation = WD_ORIENT.PORTRAIT
    section.top_margin = Inches(0.6)
    section.bottom_margin = Inches(0.6)
    section.left_margin = Inches(0.55)
    section.right_margin = Inches(0.55)

    findings = [x for x in results if is_finding(x)]
    errors = [x for x in results if is_error(x)]
    oks = [x for x in results if is_ok(x)]

    add_title_page(document, audit_name, target_url, scan_mode, pages_count)

    document.add_heading("1. Resumen ejecutivo", 1)
    document.add_paragraph(
        f"Se han ejecutado {len(results)} comprobaciones automatizadas sobre el objetivo definido. "
        f"Se han identificado {len(findings)} hallazgos que requieren revisión y "
        f"{len(errors)} errores o limitaciones de ejecución."
    )

    add_summary_table(document, findings, errors, oks)
    add_severity_table(document, findings)
    add_discovered_surface(document, pages)
    add_discovery_dictionary_section(document, discovery)
    add_auth_surface_summary(document, pages)
    add_top_findings_table(document, findings)
    add_execution_errors_table(document, errors)
    add_cases_checked(document, results)
    add_test_path_summary(document, pages, pages_count)
    add_offensive_coverage_section(document, results)
    add_detailed_findings(document, findings)
    add_conclusion(document, findings, errors, results)

    safe_name = audit_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
    file_path = f"generated_reports/{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"

    document.save(file_path)

    return file_path