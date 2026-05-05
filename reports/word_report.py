from collections import Counter, defaultdict
from datetime import datetime
import os

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt


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
    "No probado",
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
        "RESULTADOS DEL ANÁLISIS DE SEGURIDAD WEB MEDIANTE BLACKHARRIER WEB SENTINEL",
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

    table.rows[0].cells[0].text = "Severidad"
    table.rows[0].cells[1].text = "Hallazgos"

    for sev in ["Crítica", "Alta", "Media", "Baja", "Informativa"]:
        row = table.add_row().cells
        row[0].text = sev
        row[1].text = str(counts.get(sev, 0))


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
        forms = page.get("forms") or []
        forms_count = len(forms)

        observation = ""

        if classification in ["auth", "registration"]:
            if forms_count == 0:
                observation = (
                    "Ruta compatible con autenticación/registro. No se detectó formulario HTML estático; "
                    "probable renderizado cliente o envío vía API."
                )
            else:
                observation = "Ruta compatible con autenticación/registro con formulario HTML detectado."
        elif classification == "protected_redirect_to_auth":
            observation = "Ruta sensible que redirige a autenticación. Revisar control de acceso tras login."
        elif classification == "protected":
            observation = "Ruta protegida detectada. Revisar autorización y exposición."
        elif classification == "admin_candidate":
            observation = "Ruta administrativa candidata a revisión de control de acceso."
        elif classification == "api_candidate":
            observation = "Ruta candidata a API; revisar métodos, autenticación y errores."
        elif classification == "sensitive_candidate":
            observation = "Ruta sensible candidata; revisar exposición de secretos, backups o configuración."
        elif classification == "server_error":
            observation = "Error 5xx detectado; revisar filtrado de información técnica."
        elif classification == "error_disclosure_candidate":
            observation = "Respuesta con indicadores de error técnico o posible disclosure."

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
        forms_count = len(page.get("forms") or [])

        document.add_paragraph(
            f"Ruta detectada: {url} | URL final: {final_url} | HTTP: {page.get('status_code')} | "
            f"Clasificación: {page.get('classification')} | Formularios HTML estáticos detectados: {forms_count}",
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

    for i, h in enumerate(headers):
        table.rows[0].cells[i].text = h

    for item in sort_results(findings)[:25]:
        row = table.add_row().cells
        row[0].text = item.get("Severidad", "")
        row[1].text = item.get("Módulo", "")
        row[2].text = truncate(item.get("Control", ""), 90)
        row[3].text = truncate(item.get("Evidencia", ""), 220)
        row[4].text = truncate(item.get("Recomendación", ""), 220)


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
            forms_count = len(page.get("forms") or [])
            statements.append(
                f"Durante discovery se identificó la ruta {page.get('url')} "
                f"clasificada como {page.get('classification')}, con código HTTP {page.get('status_code')} "
                f"y {forms_count} formulario(s) HTML estático(s) detectado(s)."
            )

            if forms_count == 0:
                statements.append(
                    "Al no detectarse formulario HTML estático, se considera probable que el flujo de autenticación "
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


def add_detailed_findings(document, findings):
    document.add_heading("8. Detalle técnico de hallazgos", 1)

    if not findings:
        document.add_paragraph("No se identificaron hallazgos técnicos relevantes.")
        return

    for item in sort_results(findings):
        document.add_heading(
            f"{item.get('Severidad', '')} - {item.get('Módulo', '')} - {item.get('Control', '')}",
            2,
        )

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


def add_conclusion(document, findings, errors):
    document.add_heading("9. Conclusión y próximos pasos", 1)

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
    add_detailed_findings(document, findings)
    add_conclusion(document, findings, errors)

    safe_name = audit_name.replace(" ", "_").replace("/", "_").replace("\\", "_")
    file_path = f"generated_reports/{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"

    document.save(file_path)

    return file_path