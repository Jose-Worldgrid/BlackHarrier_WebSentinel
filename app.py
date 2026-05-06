import html
import traceback
from datetime import datetime

import pandas as pd
import streamlit as st

from config import APP_NAME, APP_SUBTITLE, SCAN_MODES

from scanner.http_client import HttpClient, configure_defaults
from scanner.crawler import crawl_site
from scanner.recon import scan_recon
from scanner.headers import scan_security_headers
from scanner.cookies import scan_cookies
from scanner.forms import scan_forms_from_pages
from scanner.xss import scan_reflected_xss_pages
from scanner.sqli import scan_sqli_pages
from scanner.cors import scan_cors
from scanner.methods import scan_http_methods
from scanner.csrf import scan_csrf_from_pages
from scanner.open_redirect import scan_open_redirect_pages
from scanner.sensitive_files import scan_sensitive_files
from scanner.directory_listing import scan_directory_listing
from scanner.jwt import scan_jwt_from_pages
from scanner.api_discovery import scan_api_discovery
from scanner.tls_check import scan_tls
from scanner.auth import authenticate
from scanner.url_mapping import map_urls
from scanner.tech_fingerprint import scan_technology_fingerprint
from scanner.access_control import scan_access_control
from scanner.dom_xss import scan_dom_xss
from scanner.ssrf import scan_ssrf_hints
from scanner.path_traversal import scan_path_traversal
from scanner.dependency_exposure import scan_dependency_exposure
from scanner.discovery import discover_surface
from scanner.auth_sqli import scan_auth_sqli
from scanner.ai_agent import enrich_pages_with_ai_context
from scanner.browser_auth import extract_auth_runtime_evidence

from storage.database import init_db, save_audit
from reports.word_report import generate_word_report


st.set_page_config(
    page_title=APP_NAME,
    layout="wide",
    page_icon="🦅",
    initial_sidebar_state="expanded",
)

init_db()


st.markdown("""
<style>
    :root {
        --bh-bg: #070B11;
        --bh-text: #F8FAFC;
        --bh-red: #EF4444;
    }

    .stApp {
        background:
            radial-gradient(circle at 50% 0%, rgba(30, 41, 59, 0.35), transparent 34%),
            linear-gradient(180deg, #080C12 0%, #05080D 100%);
        color: var(--bh-text);
    }

    header[data-testid="stHeader"] {
        background: transparent !important;
        height: 0 !important;
    }

    .block-container {
        max-width: none;
        padding-top: 1.2rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        padding-bottom: 2rem !important;
    }

    section[data-testid="stSidebar"] {
        width: 280px !important;
        background:
            radial-gradient(circle at 50% 0%, rgba(31, 41, 55, 0.35), transparent 42%),
            linear-gradient(180deg, #0A0F16 0%, #070B11 100%);
        border-right: 1px solid #263241;
    }

    section[data-testid="stSidebar"] > div:first-child {
        padding: 0 !important;
    }

    section[data-testid="stSidebar"] [data-testid="stSidebarHeader"] {
        display: none !important;
        height: 0 !important;
        min-height: 0 !important;
        max-height: 0 !important;
        padding: 0 !important;
        margin: 0 !important;
    }

    section[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] {
        display: none !important;
    }

    section[data-testid="stSidebar"] [data-testid="stSidebarUserContent"] {
        padding: 0 0.85rem 2rem 0.85rem !important;
    }

    .sidebar-logo-wrapper {
        margin: 0 !important;
        padding: 0 !important;
    }

    .sidebar-logo-wrapper [data-testid="stHorizontalBlock"] {
        margin: 0 !important;
        padding: 0 !important;
    }

    .sidebar-logo-wrapper [data-testid="column"] {
        padding: 0 !important;
    }

    .sidebar-logo-wrapper img {
        display: block !important;
        margin: 0 auto !important;
    }

    section[data-testid="stSidebar"] hr {
        margin: 0.1rem 0 1.25rem 0;
        border-color: rgba(148, 163, 184, 0.16);
    }

    section[data-testid="stSidebar"] [data-testid="stImage"] {
        margin-bottom: 0 !important;
        padding-bottom: 0 !important;
    }

    section[data-testid="stSidebar"] [data-testid="stImage"] img {
        margin-bottom: 0 !important;
    }

    section[data-testid="stSidebar"] h2,
    section[data-testid="stSidebar"] h3 {
        font-size: 17px;
        font-weight: 800;
        color: #F8FAFC;
        padding: 0;
        margin: 0 0 0.85rem 0;
    }

    section[data-testid="stSidebar"] label {
        color: #F8FAFC !important;
        font-size: 12px !important;
        font-weight: 700 !important;
    }

    section[data-testid="stSidebar"] input,
    section[data-testid="stSidebar"] textarea {
        background: rgba(15, 23, 42, 0.78) !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(148, 163, 184, 0.14) !important;
        border-radius: 8px !important;
        min-height: 38px;
    }

    section[data-testid="stSidebar"] input::placeholder {
        color: #A8B3C4 !important;
        opacity: 1;
    }

    section[data-testid="stSidebar"] [data-baseweb="select"] {
        background: transparent !important;
    }

    section[data-testid="stSidebar"] [data-baseweb="select"] > div {
        background: rgba(15, 23, 42, 0.78) !important;
        color: #F8FAFC !important;
        border: 1px solid rgba(148, 163, 184, 0.14) !important;
        border-radius: 8px !important;
        min-height: 38px;
        box-shadow: none !important;
    }

    section[data-testid="stSidebar"] [data-baseweb="select"] * {
        box-shadow: none !important;
    }

    section[data-testid="stSidebar"] [data-baseweb="select"] div[role="button"] {
        border: none !important;
    }

    section[data-testid="stSidebar"] [data-testid="stSlider"] {
        padding-top: 0.15rem;
    }

    section[data-testid="stSidebar"] [data-testid="stTickBar"] {
        color: #F8FAFC;
    }

    .bh-hero {
        margin: 0;
        padding: 0;
        max-width: 900px;
    }

    .bh-title {
        font-size: 40px;
        font-weight: 900;
        color: #F8FAFC;
        margin: 0 0 0.55rem 0;
        letter-spacing: 0.2px;
        line-height: 1.12;
    }

    .bh-title span {
        color: #EF4444;
    }

    .bh-subtitle {
        font-size: 18px;
        font-weight: 500;
        color: #E2E8F0;
        margin: 0 0 0.65rem 0;
    }

    .bh-author {
        font-size: 14px;
        color: #CBD5E1;
        margin: 0 0 1.1rem 0;
    }

    .bh-author span {
        color: #F8FAFC;
        font-weight: 600;
    }

    .bh-divider {
        width: 100%;
        height: 1px;
        background: rgba(148, 163, 184, 0.14);
        margin-top: 1rem;
    }

    .bh-panel {
        background: linear-gradient(135deg, #111827, #1E293B);
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #334155;
        margin-bottom: 18px;
    }

    .stButton > button {
        width: 100%;
        background: linear-gradient(90deg, #DC2626, #EF4444);
        color: white;
        border-radius: 10px;
        border: 0;
        font-weight: 800;
        padding: 0.65rem 1rem;
    }

    .stButton > button:hover {
        background: linear-gradient(90deg, #B91C1C, #EF4444);
        color: white;
        border: 0;
    }

    div[data-testid="stMetric"] {
        background: rgba(15, 23, 42, 0.62);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 14px;
        padding: 1rem;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
    }

    .bh-attack-card {
        background: #111827;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 14px;
        margin-bottom: 14px;
    }

    .bh-finish-card {
        background: #052e16;
        border: 1px solid #16a34a;
        border-radius: 12px;
        padding: 14px;
        margin-bottom: 14px;
    }

    code {
        color: #22c55e !important;
        background: rgba(15, 23, 42, 0.9) !important;
        border-radius: 6px;
        padding: 2px 5px;
    }
</style>
""", unsafe_allow_html=True)


st.markdown(
    """
    <div class="bh-hero">
        <div class="bh-title">BlackHarrier <span>Web Sentinel</span></div>
        <div class="bh-subtitle">Offensive Web Audit Platform</div>
        <div class="bh-author">by <span>Jose</span></div>
        <div class="bh-divider"></div>
    </div>
    """,
    unsafe_allow_html=True,
)


with st.sidebar:
    st.markdown('<div class="sidebar-logo-wrapper">', unsafe_allow_html=True)

    logo_col_1, logo_col_2, logo_col_3 = st.columns([0.15, 0.55, 0.15])
    with logo_col_2:
        st.image("Logo_vertical.png", width="stretch")

    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("---")
    st.header("Configuración de auditoría")

    audit_name = st.text_input(
        "Nombre de auditoría",
        value=f"Auditoría Web - {datetime.now().strftime('%Y-%m-%d')}",
    )

    target_url = st.text_input(
        "URL objetivo",
        placeholder="https://example.com",
    )

    scan_mode = st.selectbox(
        "Modo de auditoría",
        list(SCAN_MODES.keys()),
        index=1,
    )

    verify_ssl = st.checkbox(
        "Validar certificados SSL/TLS",
        value=True,
        help="Recomendado: activado. Desactívalo solo en entornos de prueba autorizados con certificados no confiables.",
    )

    sqli_intensity = st.selectbox(
        "Intensidad SQLi en login",
        [
            "Rápida - 10 payloads",
            "Normal - 30 payloads",
            "Exhaustiva - todos los payloads",
        ],
        index=1,
    )

    if sqli_intensity.startswith("Rápida"):
        max_auth_sqli_payloads = 10
    elif sqli_intensity.startswith("Normal"):
        max_auth_sqli_payloads = 30
    else:
        max_auth_sqli_payloads = None

    use_auth = st.checkbox("Usar credenciales de login")

    login_url = ""
    username = ""
    password = ""

    if use_auth:
        login_url = st.text_input("URL de login", value=target_url)
        username = st.text_input("Usuario")
        password = st.text_input("Contraseña", type="password")

    run_scan = st.button("Iniciar auditoría", type="primary")


def normalize_results(module_name, results):
    return [
        {
            "Módulo": module_name,
            "Control": item.get("control", ""),
            "Resultado": item.get("status", ""),
            "Severidad": item.get("severity", ""),
            "Descripción": item.get("description", ""),
            "Evidencia": item.get("evidence", ""),
            "Recomendación": item.get("recommendation", ""),
        }
        for item in results
    ]


def resolve_payload_limit(*limits):
    valid_limits = [limit for limit in limits if isinstance(limit, int) and limit > 0]
    return min(valid_limits) if valid_limits else None


def run_module(label, module_name, func, *args):
    with st.spinner(label):
        try:
            module_results = func(*args)

            if module_results is None:
                return normalize_results(module_name, [{
                    "control": module_name,
                    "status": "Error",
                    "severity": "Media",
                    "description": "El módulo no devolvió resultados.",
                    "evidence": "La función devolvió None.",
                    "recommendation": "Revisar que el módulo retorne siempre una lista de resultados.",
                }])

            return normalize_results(module_name, module_results)

        except Exception:
            return normalize_results(module_name, [{
                "control": module_name,
                "status": "Error",
                "severity": "Media",
                "description": "Error durante la ejecución del módulo.",
                "evidence": traceback.format_exc(),
                "recommendation": "Revisar trazas, dependencias, conectividad, argumentos del módulo y alcance.",
            }])


def is_blocked_or_error_page(page):
    url = str(page.get("final_url") or page.get("url") or "").lower()
    status = str(page.get("status_code", ""))
    html_text = " ".join([
        str(page.get("html", "")),
        str(page.get("rendered_html", "")),
        str((page.get("browser_runtime") or {}).get("html", "")),
    ]).lower()

    blocked_markers = [
        "unauthorized",
        "acceso denegado",
        "access denied",
        "forbidden",
        "no dispones de permisos",
        "no tienes permisos",
        "sin permisos",
    ]

    if status.startswith("4") and status not in ["401", "403"]:
        return True

    if any(marker in url for marker in ["unauthorized", "forbidden", "access-denied"]):
        return True

    if any(marker in html_text for marker in blocked_markers):
        return True

    return False


def is_auth_attack_page(page):
    url = str(page.get("final_url") or page.get("url") or "").lower()
    classification = str(page.get("classification", "")).lower()

    if is_blocked_or_error_page(page):
        return False

    return (
        classification == "auth"
        or "login" in url
        or "signin" in url
        or "iniciar-sesion" in url
        or "inicio-sesion" in url
    )


def is_generic_attack_page(page):
    if is_blocked_or_error_page(page):
        return False

    status = str(page.get("status_code", ""))
    return status.startswith("2") or status.startswith("3")


def add_browser_runtime_form_if_detected(page, runtime):
    browser_inputs = runtime.get("inputs") or []
    browser_buttons = runtime.get("buttons") or []

    page["browser_runtime"] = runtime
    page["browser_inputs"] = browser_inputs
    page["browser_buttons"] = browser_buttons

    has_password = any(
        str(field.get("type", "")).lower() == "password"
        or "password" in str(field).lower()
        or "contraseña" in str(field).lower()
        for field in browser_inputs
    )

    has_user = any(
        str(field.get("type", "")).lower() in ["email", "text"]
        or "email" in str(field).lower()
        or "correo" in str(field).lower()
        or "usuario" in str(field).lower()
        or "user" in str(field).lower()
        for field in browser_inputs
    )

    if has_user and has_password:
        page["forms"] = page.get("forms") or []

        already_added = any(
            isinstance(form, dict) and str(form.get("source", "")) == "browser_runtime"
            for form in page["forms"]
        )

        if not already_added:
            page["forms"].append({
                "source": "browser_runtime",
                "type": "client_side_auth_form",
                "method": "client-side/js",
                "action": "unknown_or_api",
                "fields": browser_inputs,
                "buttons": browser_buttons,
            })

        current_classification = str(page.get("classification", "")).lower()
        url = str(page.get("final_url") or page.get("url") or "").lower()

        if "admin" in url:
            page["classification"] = "admin_candidate"
        elif current_classification in ["auth", "html_candidate", ""]:
            page["classification"] = "auth"

    if runtime.get("candidate_endpoints"):
        page.setdefault("ai_context", {})
        page["ai_context"]["candidate_endpoints"] = runtime["candidate_endpoints"]
        page["ai_context"]["requires_api_endpoint_discovery"] = True

    if runtime.get("html"):
        page["rendered_html"] = runtime["html"]


if run_scan:
    if not target_url:
        st.error("Debes introducir una URL objetivo.")
        st.stop()

    all_results = []
    scan_profile = SCAN_MODES.get(scan_mode, {})
    scan_delay = float(scan_profile.get("delay", 0.35))
    scan_payload_limit = scan_profile.get("max_payloads")
    is_aggressive_mode = bool(scan_profile.get("aggressive", False))

    effective_auth_payload_limit = resolve_payload_limit(scan_payload_limit, max_auth_sqli_payloads)

    configure_defaults(delay=scan_delay, verify_ssl=verify_ssl)
    auth_client = HttpClient()

    st.markdown(
        f"""
        <div class="bh-panel">
            <b>Auditoría iniciada mediante BlackHarrier Web Sentinel</b><br>
            Autor: <b>Jose</b><br>
            Modo seleccionado: <b>{html.escape(str(scan_mode))}</b><br>
            Objetivo: <b>{html.escape(str(target_url))}</b>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if use_auth:
        auth_client, auth_results = authenticate(login_url, username, password)
        auth_client.verify_ssl = verify_ssl
        all_results.extend(normalize_results("Autenticación", auth_results))

    with st.spinner("Ejecutando crawling completo..."):
        crawler_pages = crawl_site(target_url, max_pages=None, client=auth_client)

    with st.spinner("Ejecutando discovery activo con diccionario de rutas comunes..."):
        discovery = discover_surface(
            target_url,
            client=auth_client,
            seed_pages=crawler_pages,
            max_active_checks=500 if is_aggressive_mode else 300,
        )

    pages = discovery["pages"]
    pages = enrich_pages_with_ai_context(pages)
    discovered_urls = discovery["discovered"]

    runtime_candidates = [
        page for page in pages
        if page.get("ai_context", {}).get("page_type") == "auth"
        or page.get("ai_context", {}).get("requires_browser_dom")
    ]

    if runtime_candidates:
        st.info(f"Analizando DOM dinámico con navegador en {len(runtime_candidates)} URL(s)...")
        dom_progress = st.progress(0)
        dom_status_box = st.empty()

        for index, page in enumerate(runtime_candidates, start=1):
            page_url = page.get("final_url") or page.get("url")
            dom_status_box.write(f"Renderizando con Playwright: `{page_url}`")

            try:
                runtime = extract_auth_runtime_evidence(
                    page_url,
                    headless=True,
                    timeout_ms=8000,
                )
            except Exception as exc:
                runtime = {
                    "ok": False,
                    "url": page_url,
                    "candidate_endpoints": [],
                    "inputs": [],
                    "buttons": [],
                    "network_events": [],
                    "html": "",
                    "error": f"{type(exc).__name__}: {exc}",
                }

            add_browser_runtime_form_if_detected(page, runtime)
            dom_progress.progress(index / len(runtime_candidates))

        dom_status_box.write("Análisis dinámico con navegador finalizado.")
    else:
        st.info("No se detectaron páginas que requieran análisis DOM dinámico.")

    st.success(
        f"URLs HTML analizadas: {len(pages)} | "
        f"URLs procesadas por discovery: {len(discovered_urls)}"
    )

    all_results.extend(normalize_results("Discovery", discovery["results"]))

    all_results.extend(run_module("Mapeando URLs asociadas...", "Mapa de URLs", map_urls, target_url, pages, auth_client))
    all_results.extend(run_module("Reconocimiento tecnológico...", "Reconocimiento", scan_recon, target_url))
    all_results.extend(run_module("Validando TLS/HTTPS...", "TLS/HTTPS", scan_tls, target_url))
    all_results.extend(run_module("Analizando cabeceras...", "Cabeceras de seguridad", scan_security_headers, target_url, auth_client))
    all_results.extend(run_module("Analizando cookies...", "Cookies", scan_cookies, target_url))
    all_results.extend(run_module("Analizando CORS...", "CORS", scan_cors, target_url))
    all_results.extend(run_module("Analizando métodos HTTP...", "Métodos HTTP", scan_http_methods, target_url))
    all_results.extend(run_module("Buscando recursos sensibles...", "Recursos sensibles", scan_sensitive_files, target_url))
    all_results.extend(run_module("Buscando directory listing...", "Directory Listing", scan_directory_listing, target_url))
    all_results.extend(run_module("Descubriendo APIs...", "API Discovery", scan_api_discovery, target_url, pages))
    all_results.extend(run_module("Analizando formularios...", "Formularios", scan_forms_from_pages, pages))
    all_results.extend(run_module("Analizando CSRF...", "CSRF", scan_csrf_from_pages, pages))

    attackable_pages = [page for page in pages if is_generic_attack_page(page)]
    auth_attack_pages = [page for page in pages if is_auth_attack_page(page)]

    st.markdown("### Ejecución ofensiva en tiempo real")
    attack_status = st.empty()
    attack_progress = st.empty()

    def attack_progress_event(event):
        current = int(event.get("current", 0))
        total = max(int(event.get("total", 1)), 1)

        endpoints = event.get("candidate_endpoints", [])
        raw_target = event.get("target", event.get("login_url", ""))
        if endpoints:
            raw_target = endpoints[0]

        phase = html.escape(str(event.get("phase", "Ataque")))
        technique = html.escape(str(event.get("technique", "")))
        target = html.escape(str(raw_target))
        field = html.escape(str(event.get("field", "")))
        payload = html.escape(str(event.get("payload", "")))
        detail = html.escape(str(event.get("detail", "")))

        attack_progress.progress(min(current / total, 1.0))

        field_line = f"<b>Campo/parámetro:</b> <code>{field}</code><br>" if field else ""

        attack_status.markdown(
            f"""
            <div class="bh-attack-card">
                <b>Fase:</b> {phase}<br>
                <b>Técnica:</b> {technique}<br>
                <b>Objetivo:</b> <code>{target}</code><br>
                {field_line}
                <b>Payload:</b> <code>{payload}</code><br>
                <b>Detalle:</b> {detail}<br>
                <b>Progreso:</b> {current}/{total}
            </div>
            """,
            unsafe_allow_html=True,
        )

    def attack_finished(message):
        attack_progress.empty()
        attack_status.markdown(
            f"""
            <div class="bh-finish-card">
                <b>{html.escape(str(message))}</b>
            </div>
            """,
            unsafe_allow_html=True,
        )

    all_results.extend(run_module(
        "Probando XSS reflejado...",
        "XSS reflejado",
        scan_reflected_xss_pages,
        attackable_pages,
        scan_payload_limit,
    ))

    all_results.extend(run_module(
        "Probando SQL Injection...",
        "SQL Injection",
        scan_sqli_pages,
        attackable_pages,
        scan_payload_limit,
    ))

    with st.spinner(f"Probando SQLi en autenticación ({sqli_intensity})..."):
        auth_sqli_results = scan_auth_sqli(
            pages=auth_attack_pages,
            client=auth_client,
            max_payloads=effective_auth_payload_limit,
            headless=True,
            progress_callback=attack_progress_event,
        )

    all_results.extend(normalize_results(
        "SQL Injection Auth (Browser)",
        auth_sqli_results,
    ))

    attack_finished("Ejecución ofensiva finalizada.")

    all_results.extend(run_module("Probando Open Redirect...", "Open Redirect", scan_open_redirect_pages, attackable_pages))
    all_results.extend(run_module("Analizando JWT expuestos...", "JWT", scan_jwt_from_pages, attackable_pages))

    all_results.extend(run_module(
        "Fingerprinting avanzado de tecnologías...",
        "Fingerprinting avanzado",
        scan_technology_fingerprint,
        target_url,
        pages,
    ))

    all_results.extend(run_module(
        "Analizando control de acceso...",
        "Control de acceso",
        scan_access_control,
        target_url,
        pages,
        auth_client,
    ))

    all_results.extend(run_module(
        "Analizando XSS DOM/frontend...",
        "XSS DOM",
        scan_dom_xss,
        attackable_pages,
    ))

    if is_aggressive_mode:
        all_results.extend(run_module(
            "Analizando posibles SSRF...",
            "SSRF",
            scan_ssrf_hints,
            attackable_pages,
        ))

        all_results.extend(run_module(
            "Analizando path traversal...",
            "Path Traversal",
            scan_path_traversal,
            attackable_pages,
        ))
    else:
        all_results.extend(normalize_results("SSRF", [{
            "control": "SSRF",
            "status": "No probado",
            "severity": "Informativa",
            "description": "Módulo omitido por modo de auditoría no agresivo.",
            "evidence": f"Modo: {scan_mode}",
            "recommendation": "Usar modo agresivo autorizado si necesitas cobertura de pruebas más intrusivas.",
        }]))

        all_results.extend(normalize_results("Path Traversal", [{
            "control": "Path Traversal",
            "status": "No probado",
            "severity": "Informativa",
            "description": "Módulo omitido por modo de auditoría no agresivo.",
            "evidence": f"Modo: {scan_mode}",
            "recommendation": "Usar modo agresivo autorizado si necesitas cobertura de pruebas más intrusivas.",
        }]))

    all_results.extend(run_module(
        "Analizando exposición de runtime/dependencias...",
        "Exposición de dependencias",
        scan_dependency_exposure,
        target_url,
    ))

    df = pd.DataFrame(all_results)

    st.session_state["last_audit_df"] = df
    st.session_state["last_audit_results"] = all_results
    st.session_state["last_audit_pages"] = pages
    st.session_state["last_audit_discovery"] = discovery

    st.subheader("Resultados")
    finding_statuses = ["Hallazgo", "Posible hallazgo"]
    total_checks = len(df)
    total_findings = len(df[df["Resultado"].isin(finding_statuses)])
    total_errors = len(df[df["Resultado"] == "Error"])

    pages_count = len(pages)

    m1, m2, m3, m4 = st.columns(4)

    m1.metric("URLs HTML analizadas", pages_count)
    m2.metric("Pruebas ejecutadas", total_checks)
    m3.metric("Hallazgos", total_findings)
    m4.metric("Errores", total_errors)

    st.dataframe(df, width="stretch")

    st.subheader("Resumen por severidad")
    severity_summary = (
        df[df["Resultado"].isin(finding_statuses)]["Severidad"]
        .value_counts()
        .reset_index()
    )
    severity_summary.columns = ["Severidad", "Cantidad"]
    st.dataframe(severity_summary, width="stretch")

    st.subheader("Resumen por módulo")
    module_summary = (
        df.groupby(["Módulo", "Resultado", "Severidad"])
        .size()
        .reset_index(name="Cantidad")
    )
    st.dataframe(module_summary, width="stretch")

    save_audit(audit_name, target_url, all_results)

    report_path = generate_word_report(
        audit_name=audit_name,
        target_url=target_url,
        results=all_results,
        pages=pages,
        discovery=discovery,
        pages_count=len(pages),
        scan_mode=scan_mode,
    )

    st.session_state["last_report_path"] = report_path

    with open(report_path, "rb") as file:
        st.download_button(
            label="Descargar informe Word",
            data=file,
            file_name=report_path.split("/")[-1],
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            on_click="ignore",
        )
elif st.session_state.get("last_audit_df") is not None:
    df = st.session_state["last_audit_df"]
    report_path = st.session_state.get("last_report_path")

    st.subheader("Resultados de la última auditoría")
    st.dataframe(df, width="stretch")

    if report_path:
        with open(report_path, "rb") as file:
            st.download_button(
                label="Descargar informe Word",
                data=file,
                file_name=report_path.split("/")[-1],
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                on_click="ignore",
            )
