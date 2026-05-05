import streamlit as st
import pandas as pd
import traceback
from scanner.http_client import HttpClient
from datetime import datetime

from config import APP_NAME, APP_SUBTITLE, SCAN_MODES

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

from storage.database import init_db, save_audit
from reports.word_report import generate_word_report
from scanner.discovery import discover_surface
from scanner.browser_auth import scan_browser_auth_sqli


st.set_page_config(
    page_title=APP_NAME,
    layout="wide",
    page_icon="🦅",
    initial_sidebar_state="expanded"
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
    unsafe_allow_html=True
)


with st.sidebar:
    st.markdown('<div class="sidebar-logo-wrapper">', unsafe_allow_html=True)

    logo_col_1, logo_col_2, logo_col_3 = st.columns([0.15, 0.55, 0.15])
    with logo_col_2:
        st.image("Logo_vertical.png", width="stretch")

    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")

    st.header("Configuración de auditoría")

    audit_name = st.text_input(
        "Nombre de auditoría",
        value=f"Auditoría Web - {datetime.now().strftime('%Y-%m-%d')}"
    )

    target_url = st.text_input(
        "URL objetivo",
        placeholder="https://example.com"
    )

    scan_mode = st.selectbox(
        "Modo de auditoría",
        list(SCAN_MODES.keys()),
        index=1
    )

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
            "Recomendación": item.get("recommendation", "")
        }
        for item in results
    ]


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
                    "recommendation": "Revisar que el módulo retorne siempre una lista de resultados."
                }])

            return normalize_results(module_name, module_results)

        except Exception:
            return normalize_results(module_name, [{
                "control": module_name,
                "status": "Error",
                "severity": "Media",
                "description": "Error durante la ejecución del módulo.",
                "evidence": traceback.format_exc(),
                "recommendation": "Revisar trazas, dependencias, conectividad, argumentos del módulo y alcance."
            }])


if run_scan:
    if not target_url:
        st.error("Debes introducir una URL objetivo.")
        st.stop()

    all_results = []
    auth_client = HttpClient(verify_ssl=False)

    st.markdown(
        f"""
        <div class="bh-panel">
            <b>Auditoría iniciada mediante BlackHarrier Web Sentinel</b><br>
            Autor: <b>Jose</b><br>
            Modo seleccionado: <b>{scan_mode}</b><br>
            Objetivo: <b>{target_url}</b>
        </div>
        """,
        unsafe_allow_html=True
    )

    if use_auth:
        auth_client, auth_results = authenticate(login_url, username, password)
        auth_client.verify_ssl = False
        all_results.extend(normalize_results("Autenticación", auth_results))

    with st.spinner("Ejecutando crawling completo..."):
        crawler_pages = crawl_site(target_url, max_pages=None, client=auth_client)

    with st.spinner("Ejecutando discovery activo con diccionario de rutas comunes..."):
        discovery = discover_surface(
            target_url,
            client=auth_client,
            seed_pages=crawler_pages,
            max_active_checks=300
        )

    pages = discovery["pages"]
    discovered_urls = discovery["discovered"]

    st.success(
        f"URLs HTML analizadas: {len(pages)} | "
        f"URLs procesadas por discovery: {len(discovered_urls)}"
    )

    all_results.extend(normalize_results(
        "Discovery",
        discovery["results"]
    ))

    all_results.extend(run_module("Mapeando URLs asociadas...", "Mapa de URLs", map_urls, target_url, pages, auth_client))
    all_results.extend(run_module("Reconocimiento tecnológico...", "Reconocimiento", scan_recon, target_url))
    all_results.extend(run_module("Validando TLS/HTTPS...", "TLS/HTTPS", scan_tls, target_url))
    all_results.extend(run_module("Analizando cabeceras...","Cabeceras de seguridad",scan_security_headers,target_url,auth_client))
    all_results.extend(run_module("Analizando cookies...", "Cookies", scan_cookies, target_url))
    all_results.extend(run_module("Analizando CORS...", "CORS", scan_cors, target_url))
    all_results.extend(run_module("Analizando métodos HTTP...", "Métodos HTTP", scan_http_methods, target_url))
    all_results.extend(run_module("Buscando recursos sensibles...", "Recursos sensibles", scan_sensitive_files, target_url))
    all_results.extend(run_module("Buscando directory listing...", "Directory Listing", scan_directory_listing, target_url))
    all_results.extend(run_module("Descubriendo APIs...", "API Discovery", scan_api_discovery, target_url, pages))
    all_results.extend(run_module("Analizando formularios...", "Formularios", scan_forms_from_pages, pages))
    all_results.extend(run_module("Analizando CSRF...", "CSRF", scan_csrf_from_pages, pages))
    all_results.extend(run_module("Probando XSS reflejado...", "XSS reflejado", scan_reflected_xss_pages, pages))
    all_results.extend(run_module("Probando SQL Injection...", "SQL Injection", scan_sqli_pages, pages))
    all_results.extend(run_module(
        "Explotando autenticación (SQLi + bypass con navegador)...",
        "SQL Injection Auth (Browser)",
        scan_browser_auth_sqli,
        pages,
        None,   # max_payloads = None → TODA la wordlist
        True    # headless
    ))
    all_results.extend(run_module("Probando Open Redirect...", "Open Redirect", scan_open_redirect_pages, pages))
    all_results.extend(run_module("Analizando JWT expuestos...", "JWT", scan_jwt_from_pages, pages))

    all_results.extend(run_module(
        "Fingerprinting avanzado de tecnologías...",
        "Fingerprinting avanzado",
        scan_technology_fingerprint,
        target_url,
        pages
    ))

    all_results.extend(run_module(
        "Analizando control de acceso...",
        "Control de acceso",
        scan_access_control,
        target_url,
        pages,
        auth_client
    ))

    all_results.extend(run_module(
        "Analizando XSS DOM/frontend...",
        "XSS DOM",
        scan_dom_xss,
        pages
    ))

    all_results.extend(run_module(
        "Analizando posibles SSRF...",
        "SSRF",
        scan_ssrf_hints,
        pages
    ))

    all_results.extend(run_module(
        "Analizando path traversal...",
        "Path Traversal",
        scan_path_traversal,
        pages
    ))

    all_results.extend(run_module(
        "Analizando exposición de runtime/dependencias...",
        "Exposición de dependencias",
        scan_dependency_exposure,
        target_url
    ))

    df = pd.DataFrame(all_results)

    st.subheader("Resultados")
    finding_statuses = ["Hallazgo", "Posible hallazgo"]
    total_checks = len(df)
    total_findings = len(df[df["Resultado"].isin(finding_statuses)])
    total_errors = len(df[df["Resultado"] == "Error"])
    high_critical = len(df[df["Resultado"].isin(finding_statuses) & df["Severidad"].isin(["Crítica", "Alta"])
    ])

    pages_count = len(pages)

    m1, m2, m3, m4 = st.columns(4)

    m1.metric("URLs HTML analizadas", pages_count)
    m2.metric("Pruebas ejecutadas", total_checks)
    m3.metric("Hallazgos", total_findings)
    m4.metric("Errores", total_errors)

    st.dataframe(df, width="stretch")

    st.subheader("Resumen por severidad")
    severity_summary = df[df["Resultado"].isin(finding_statuses)]["Severidad"].value_counts().reset_index()
    severity_summary.columns = ["Severidad", "Cantidad"]
    st.dataframe(severity_summary, width="stretch")

    st.subheader("Resumen por módulo")
    module_summary = df.groupby(["Módulo", "Resultado", "Severidad"]).size().reset_index(name="Cantidad")
    st.dataframe(module_summary, width="stretch")

    save_audit(audit_name, target_url, all_results)

    report_path = generate_word_report(
        audit_name=audit_name,
        target_url=target_url,
        results=all_results,
        pages=pages,
        discovery=discovery,
        pages_count=len(pages),
        scan_mode=scan_mode
    )
    with open(report_path, "rb") as file:
        st.download_button(
            label="Descargar informe Word",
            data=file,
            file_name=report_path.split("/")[-1],
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )