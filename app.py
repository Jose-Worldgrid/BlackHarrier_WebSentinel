import html
import os
import re
import traceback
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime
from requests.utils import dict_from_cookiejar

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
from scanner.ssti import scan_ssti
from scanner.ssrf import scan_ssrf_hints
from scanner.path_traversal import scan_path_traversal
from scanner.dependency_exposure import scan_dependency_exposure
from scanner.discovery import discover_surface
from scanner.auth_sqli import scan_auth_sqli
from scanner import network_recon
from scanner.user_enum import scan_user_enumeration
from scanner.port_services import scan_port_services
from scanner.vuln_correlation import scan_vulnerability_correlation
from scanner.nmap_scanner import run_nmap_recon
from scanner.nessus_client import NessusConfig, run_nessus_assessment
from scanner.free_assessment import FreeAssessment
from scanner.cve_lookup import CVELookup
from scanner.offensive_intel import (
    collect_external_scan_targets,
    build_ai_recon_contract,
    contract_to_result,
    build_asset_intel_rows,
)
from scanner.ai_agent import (
    enrich_pages_with_ai_context,
    record_audit_feedback,
    AdaptiveOrchestrator,
)
from scanner.ai_agent.memory import load_memory

from storage.database import init_db, save_audit
from reports.word_report import generate_word_report


st.set_page_config(
    page_title=APP_NAME,
    layout="wide",
    page_icon="🦅",
    initial_sidebar_state="expanded",
)

init_db()


def _configure_http_defaults_compat(*, delay=None, verify_ssl=None, proxy_url=None):
    """Handle both new and legacy configure_defaults signatures."""
    try:
        configure_defaults(delay=delay, verify_ssl=verify_ssl, proxy_url=proxy_url)
    except TypeError as err:
        if "proxy_url" not in str(err):
            raise
        configure_defaults(delay=delay, verify_ssl=verify_ssl)


def _get_report_bytes_if_available(report_path):
    if not report_path:
        return None
    if not os.path.exists(report_path):
        return None
    try:
        with open(report_path, "rb") as file:
            return file.read()
    except Exception:
        return None


def _normalize_target_url(raw_url: str) -> str:
    """Normalize user input to a canonical absolute HTTP(S) URL."""
    text = str(raw_url or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}".rstrip("/") or f"{parsed.scheme}://{parsed.netloc}"


def _extract_auth_runtime_evidence_safe(page_url, timeout_ms=8000, headless=True):
    """Lazy-load Playwright helper to avoid blocking app startup on heavy imports."""
    try:
        from scanner.browser_auth import extract_auth_runtime_evidence

        return extract_auth_runtime_evidence(page_url, headless=headless, timeout_ms=timeout_ms)
    except Exception as exc:
        return {
            "ok": False,
            "url": page_url,
            "candidate_endpoints": [],
            "inputs": [],
            "buttons": [],
            "network_events": [],
            "html": "",
            "error": f"{type(exc).__name__}: {exc}",
        }


def _auto_detect_login_url(target_url, client, max_pages=80):
    """Find likely login endpoint from crawled pages when login URL is not provided."""
    auth_keywords = ["login", "signin", "auth", "session", "iniciar-sesion", "inicio-sesion"]
    register_keywords = ["register", "signup", "registro", "alta"]

    try:
        pages, _ = crawl_site(target_url, max_pages=max_pages, client=client)
    except Exception as exc:
        return "", {
            "control": "Autenticación - autodetección",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudo ejecutar la autodetección de URL de login.",
            "evidence": str(exc),
            "recommendation": "Indicar URL de login manualmente.",
        }

    best_url = ""
    best_score = -1
    checked = 0

    for page in pages or []:
        url = str(page.get("final_url") or page.get("url") or "")
        if not url:
            continue
        checked += 1

        lower_url = url.lower()
        html_body = str(page.get("html") or "").lower()
        classification = str(page.get("classification") or "").lower()

        score = 0
        if any(k in lower_url for k in auth_keywords):
            score += 3
        if any(k in lower_url for k in register_keywords):
            score -= 2
        if "password" in html_body:
            score += 4
        if any(k in html_body for k in ["name=\"email\"", "name=\"username\"", "type=\"email\""]):
            score += 2
        if "auth" in classification:
            score += 2

        if score > best_score:
            best_score = score
            best_url = url

    if best_url and best_score >= 4:
        return best_url, {
            "control": "Autenticación - autodetección",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Se detectó automáticamente una URL candidata de login.",
            "evidence": f"Login detectado: {best_url} | Score: {best_score} | URLs analizadas: {checked}",
            "recommendation": "Si no corresponde al login real, indicar URL manualmente.",
        }

    return "", {
        "control": "Autenticación - autodetección",
        "status": "No evidenciado",
        "severity": "Baja",
        "description": "No se detectó un login claro durante el reconocimiento inicial.",
        "evidence": f"URLs analizadas: {checked} | Mejor score observado: {best_score}",
        "recommendation": "Indicar URL de login manualmente para ampliar cobertura autenticada.",
    }


def _collect_login_candidates(target_url, pages, manual_login_url=""):
    candidates = []
    if manual_login_url:
        candidates.append(manual_login_url.strip())

    auth_markers = ["login", "signin", "auth", "session", "iniciar-sesion", "inicio-sesion"]
    reg_markers = ["register", "signup", "registro", "alta"]

    for page in pages or []:
        url = str(page.get("final_url") or page.get("url") or "").strip()
        if not url:
            continue
        lower_url = url.lower()
        classification = str(page.get("classification") or "").lower()
        has_auth_hint = "auth" in classification or any(x in lower_url for x in auth_markers)
        has_reg_hint = "registration" in classification or any(x in lower_url for x in reg_markers)
        if has_auth_hint and not has_reg_hint:
            candidates.append(url)

    if not candidates:
        candidates.append(target_url)

    # Add stable login path variants early to improve auth reliability.
    seeds = [manual_login_url.strip()] if manual_login_url else []
    seeds.extend(candidates)
    for seed in seeds:
        raw = (seed or "").strip()
        if not raw:
            continue
        parsed = urlparse(raw)
        if not parsed.scheme or not parsed.netloc:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidates.append(f"{base}/login")
        candidates.append(f"{base}/es/login")

    # Preserve order while deduplicating, but prioritize stable login paths.
    unique = list(dict.fromkeys(candidates))
    original_pos = {url: idx for idx, url in enumerate(unique)}

    def _login_priority(url):
        path = urlparse(str(url)).path.lower().rstrip("/")
        if path == "/login":
            return 0
        if path == "/es/login":
            return 1
        if "login" in path or "signin" in path:
            return 2
        return 3

    ordered = sorted(unique, key=lambda u: (_login_priority(u), original_pos[u]))
    return ordered[:8]


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
        index=list(SCAN_MODES.keys()).index("Full") if "Full" in SCAN_MODES else 1,
    )

    parity_nmap_nessus = False
    st.caption("BlackHarrier Core activo: flujo integral obligatorio (reconocimiento + crawling + mapeo + explotación controlada).")

    verify_ssl = st.checkbox(
        "Validar certificados SSL/TLS",
        value=True,
        help="Recomendado: activado. Desactívalo solo en entornos de prueba autorizados con certificados no confiables.",
    )

    use_burp_proxy = st.checkbox(
        "Usar proxy Burp Suite",
        value=False,
        help="Enruta tráfico HTTP/HTTPS de la auditoría por un proxy (ej. Burp en 127.0.0.1:8080).",
    )

    burp_proxy_url = st.text_input(
        "URL proxy (Burp)",
        value="http://127.0.0.1:8080",
        disabled=not use_burp_proxy,
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

    strict_fp_mode = st.checkbox(
        "Modo estricto anti-falsos positivos",
        value=True,
        help=(
            "Aumenta exigencia de corroboración para posibles hallazgos, "
            "sin ocultar ni descartar hallazgos importantes."
        ),
    )

    authorized_engagement = True
    offensive_scope_ack = True

    use_auth = st.checkbox("Usar credenciales de login")

    login_url = ""
    username = ""
    password = ""

    if use_auth:
        login_url = st.text_input(
            "URL de login (opcional)",
            value="",
            placeholder="https://objetivo.com/login",
            help="Si lo dejas vacío, el scanner intentará detectarla automáticamente.",
        )
        username = st.text_input("Usuario")
        password = st.text_input("Contraseña", type="password")

    mode_defaults = SCAN_MODES.get(scan_mode, {})

    # Motor unificado: BlackHarrier Core. Nmap puede enriquecer en segundo plano si está disponible.
    import shutil as _shutil
    import os as _os
    # shutil.which may miss Nmap if PATH was not refreshed after install.
    # Check known Windows install locations as fallback.
    _NMAP_FALLBACK_PATHS = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    _nmap_bin = (
        _shutil.which("nmap.exe")
        or _shutil.which("nmap")
        or next((p for p in _NMAP_FALLBACK_PATHS if _os.path.isfile(p)), None)
    )
    enable_nmap = bool(_nmap_bin)
    nmap_profile = str(mode_defaults.get("nmap_profile", "DEEP"))
    use_free_scanner = True

    st.markdown("**Profundidad del escaneo**")
    free_scanner_depth = st.radio(
        "Nivel",
        options=["Rápido", "Completo"],
        index=1,
        help="Rápido: menor tiempo. Completo: mayor cobertura de red y correlación.",
    )

    if free_scanner_depth == "Rápido":
        nmap_profile = "SAFE"
        include_udp = False
    else:
        nmap_profile = "AGGRESSIVE" if _nmap_bin else "DEEP"
        include_udp = True

    nmap_timeout_seconds = 420
    nmap_scripts = ""

    # Auto-configuración de Nessus (sin UI adicional): se activa cuando hay credenciales en entorno.
    # Variables soportadas: NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY, NESSUS_BASE_URL,
    # NESSUS_VERIFY_SSL, NESSUS_POLL_SECONDS, NESSUS_TEMPLATE_UUID.
    nessus_mode = "nessus-local"
    nessus_base_url = str(os.getenv("NESSUS_BASE_URL", "https://localhost:8834")).strip()
    nessus_access_key = str(os.getenv("NESSUS_ACCESS_KEY", "")).strip()
    nessus_secret_key = str(os.getenv("NESSUS_SECRET_KEY", "")).strip()
    nessus_verify_ssl = str(os.getenv("NESSUS_VERIFY_SSL", "false")).strip().lower() in {"1", "true", "yes", "on"}
    try:
        nessus_poll_seconds = int(str(os.getenv("NESSUS_POLL_SECONDS", "180")).strip() or "180")
    except Exception:
        nessus_poll_seconds = 180
    nessus_template_uuid = str(os.getenv("NESSUS_TEMPLATE_UUID", "basic")).strip() or "basic"
    enable_nessus = bool(nessus_access_key and nessus_secret_key)

    st.caption("BlackHarrier Scanner integrado: puertos, fingerprinting, CVE y análisis SSL/TLS ejecutados en cada auditoría.")
    if enable_nessus:
        st.caption("Nessus integrado automáticamente para cobertura ampliada de vulnerabilidades.")

    # ── Agente IA – Exploit Suggester ────────────────────────────────────
    st.markdown("**Agente IA – Propuesta de exploits**")
    import shutil as _shutil2
    _ollama_bin = _shutil2.which("ollama") or _shutil2.which("ollama.exe")
    if _ollama_bin:
        enable_exploit_ai = st.checkbox(
            "Activar propuesta de exploits con IA",
            value=True,
            help="Usa un modelo local (Ollama) para generar PoC y análisis de exploits a partir de los CVEs encontrados.",
        )
        exploit_ai_model = st.selectbox(
            "Modelo Ollama",
            options=["llama3", "mistral", "codellama", "llama3:8b", "mistral:7b"],
            index=0,
            disabled=not enable_exploit_ai,
            help="Modelo local de Ollama. Asegúrate de haberlo descargado con 'ollama pull <modelo>'.",
        )
    else:
        st.caption("Ollama no detectado – el agente IA usará plantillas offline. Instala Ollama para análisis enriquecido.")
        enable_exploit_ai = st.checkbox("Activar propuesta de exploits (modo offline)", value=True)
        exploit_ai_model = "llama3"

    run_scan = st.button(
        "Iniciar auditoría",
        type="primary",
    )


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
            "Fase": item.get("phase", _module_to_phase(module_name)),
            "Confianza": item.get("confidence", _result_confidence(item)),
            "Tipo": item.get("finding_type", _result_type(item)),
        }
        for item in results
    ]


def _module_to_phase(module_name):
    phase_map = {
        "Autenticación": "Acceso inicial",
        "Enumeración de usuarios": "Enumeración",
        "Crawler": "Reconocimiento",
        "Discovery": "Reconocimiento",
        "Discovery post-login": "Post-login Discovery",
        "Mapa de URLs": "Reconocimiento",
        "Reconocimiento": "Reconocimiento",
        "Red e infraestructura": "Reconocimiento",
        "Puertos y servicios": "Reconocimiento",
        "Correlación de vulnerabilidades": "Reconocimiento",
        "Nmap reconnaissance": "Reconocimiento",
        "Nessus/Tenable": "Reconocimiento",
        "Correlación IA ofensiva": "Reconocimiento",
        "Fingerprinting avanzado": "Reconocimiento",
        "Cabeceras de seguridad": "Reconocimiento",
        "Cookies": "Reconocimiento",
        "CORS": "Reconocimiento",
        "Métodos HTTP": "Reconocimiento",
        "API Discovery": "Enumeración",
        "Formularios": "Enumeración",
        "CSRF": "Explotación",
        "XSS reflejado": "Explotación",
        "SQL Injection": "Explotación",
        "SQL Injection Auth (Browser)": "Explotación",
        "Open Redirect": "Explotación",
        "XSS DOM": "Explotación",
        "SSTI": "Explotación",
        "SSRF": "Explotación",
        "Path Traversal": "Explotación",
        "Control de acceso": "Post-explotación",
        "JWT": "Post-explotación",
        "Exposición de dependencias": "Post-explotación",
        "Aseguramiento ofensivo": "Aseguramiento",
    }
    return phase_map.get(str(module_name or "").strip(), "Otros")


def _result_confidence(item):
    """Return a normalized confidence score in the [0.0, 1.0] range."""
    status = str(item.get("status", "") or "").strip().lower()
    severity = str(item.get("severity", "") or "").strip().lower()
    evidence = str(item.get("evidence", "") or "").lower()
    description = str(item.get("description", "") or "").lower()

    score = 0.15
    if status == "hallazgo":
        score += 0.45
    elif status == "posible hallazgo":
        score += 0.30
    elif status == "detectado":
        score += 0.25
    elif status == "correcto":
        score += 0.30
    elif status == "no evidenciado":
        score += 0.10

    if severity in {"crítica", "critica"}:
        score += 0.15
    elif severity == "alta":
        score += 0.12
    elif severity == "media":
        score += 0.08
    elif severity == "baja":
        score += 0.04

    if any(token in evidence for token in ["http://", "https://", "payload", "status", "código", "code", "marker", "marcador"]):
        score += 0.15
    if any(token in description for token in ["confirm", "validated", "detectado", "reflejado", "redirección", "token"]):
        score += 0.08

    return round(max(0.0, min(score, 1.0)), 2)


def _result_type(item):
    status = str(item.get("status", "") or "").strip().lower()
    severity = str(item.get("severity", "") or "").strip().lower()

    if status == "hallazgo":
        return "confirmado"
    if status == "posible hallazgo":
        return "indicativo"
    if status in {"correcto", "no evidenciado", "comprobado", "detectado"}:
        return "evidencia"
    if status == "error":
        return "operativo"
    if severity in {"crítica", "critica", "alta"}:
        return "riesgo"
    return "informativo"


def resolve_payload_limit(*limits):
    valid_limits = [limit for limit in limits if isinstance(limit, int) and limit > 0]
    return min(valid_limits) if valid_limits else None


def sanitize_module_results(module_results):
    """Pass-through: results are already precise from each scanner module."""
    return [dict(item or {}) for item in module_results or []]


def run_module(label, module_name, func, *args):
    with st.spinner(label):
        for attempt in range(1, 4):
            try:
                module_results = func(*args)

                if module_results is None:
                    if attempt < 3:
                        continue
                    return normalize_results(module_name, [{
                        "control": module_name,
                        "status": "Error",
                        "severity": "Media",
                        "description": "El módulo no devolvió resultados tras reintentos.",
                        "evidence": "La función devolvió None.",
                        "recommendation": "Revisar implementación del módulo.",
                    }])

                return normalize_results(module_name, sanitize_module_results(module_results))

            except Exception:
                if attempt < 3:
                    continue
                return normalize_results(module_name, [{
                    "control": module_name,
                    "status": "Error",
                    "severity": "Media",
                    "description": "Error inesperado en el módulo tras reintentos automáticos.",
                    "evidence": traceback.format_exc(),
                    "recommendation": "Revisar trazas y dependencias del módulo.",
                }])


def _run_raw(func, *args):
    """Execute a scanner function without Streamlit UI — safe for ThreadPoolExecutor."""
    result = func(*args)
    return result if result is not None else []


def run_offensive_module(label, module_name, func, pages, *args):
    # Always execute offensive modules at least once, even when discovered pages are empty.
    # This prevents "No probado" due to empty scope and keeps the report conclusive.
    effective_pages = list(pages or [])

    if not effective_pages:
        fallback_target = str(st.session_state.get("_target_url") or "").strip()
        if fallback_target:
            effective_pages = [{
                "url": fallback_target,
                "final_url": fallback_target,
                "status_code": 200,
                "html": "",
                "forms": [],
                "classification": "fallback_target",
            }]

    module_output = run_module(label, module_name, func, effective_pages, *args)
    if module_output:
        return module_output

    return normalize_results(module_name, [{
        "control": module_name,
        "status": "No evidenciado",
        "severity": "Informativa",
        "description": "Prueba ejecutada sin evidencia de explotación en esta ejecución.",
        "evidence": f"Objetivos evaluados: {len(effective_pages)}",
        "recommendation": "Mantener monitorización y repetir tras cambios de versión o configuración.",
    }])


def _safe_lower(value):
    return str(value or "").strip().lower()


def _priority_weight(priority):
    priority = _safe_lower(priority)
    if priority == "high":
        return 3.0
    if priority == "medium":
        return 2.0
    if priority == "low":
        return 1.0
    return 1.4


def _normalize_attack_name(name):
    aliases = {
        "sql injection": "SQL Injection",
        "auth_sqli": "SQL Injection Auth (Browser)",
        "sql injection auth (browser)": "SQL Injection Auth (Browser)",
        "xss": "XSS reflejado",
        "xss reflejado": "XSS reflejado",
        "xss dom": "XSS DOM",
        "csrf": "CSRF",
        "idor": "Control de acceso",
        "control de acceso": "Control de acceso",
        "jwt": "JWT",
        "open redirect": "Open Redirect",
        "ssrf": "SSRF",
        "path traversal": "Path Traversal",
        "ssti": "SSTI",
        "api discovery": "API Discovery",
        "exposición de dependencias": "Exposición de dependencias",
        "dependencia exposure": "Exposición de dependencias",
    }
    text = _safe_lower(name)
    return aliases.get(text, str(name or "").strip())


def _collect_ai_preferences(pages):
    preferences = {}

    for page in pages or []:
        ai_context = page.get("ai_context") or {}
        for attack in ai_context.get("recommended_attacks") or []:
            module_name = _normalize_attack_name(attack.get("name"))
            if not module_name:
                continue

            priority = attack.get("priority", "medium")
            confidence = float(attack.get("confidence", 0.0) or 0.0)
            score = _priority_weight(priority) + min(confidence, 1.0)

            preferences[module_name] = preferences.get(module_name, 0.0) + score

    return preferences


def _extract_target_features(pages):
    features = {
        "has_forms": False,
        "has_query_params": False,
        "has_auth": False,
        "has_api": False,
        "has_admin": False,
        "has_dynamic_dom": False,
    }

    for page in pages or []:
        url = str(page.get("final_url") or page.get("url") or "")
        ai_context = page.get("ai_context") or {}
        page_type = _safe_lower(ai_context.get("page_type") or page.get("classification"))

        if page.get("forms") or (page.get("browser_runtime") or {}).get("inputs"):
            features["has_forms"] = True

        if "?" in url:
            features["has_query_params"] = True

        if page_type in ["auth", "registration", "protected", "protected_redirect_to_auth"]:
            features["has_auth"] = True

        if page_type in ["api_candidate", "api"] or "/api" in url.lower():
            features["has_api"] = True

        if page_type in ["admin_candidate", "admin"] or any(token in url.lower() for token in ["admin", "dashboard", "panel"]):
            features["has_admin"] = True

        if ai_context.get("requires_browser_dom") or page.get("rendered_html"):
            features["has_dynamic_dom"] = True

    return features


def _memory_module_score(memory, module_name):
    stats = (memory.get("attack_stats") or {}).get(module_name, {})
    attempts = int(stats.get("attempts", 0) or 0)
    findings = int(stats.get("findings", 0) or 0)
    errors = int(stats.get("errors", 0) or 0)

    if attempts <= 0:
        return 0.0

    finding_rate = findings / attempts
    reliability = max(0.0, 1.0 - (errors / attempts))
    return (finding_rate * 0.75) + (reliability * 0.25)


def _contextual_module_boost(module_name, features):
    boost = 0.0

    if features["has_forms"] and module_name in ["SQL Injection", "XSS reflejado", "CSRF", "SSTI"]:
        boost += 1.1

    if features["has_query_params"] and module_name in ["Open Redirect", "SQL Injection", "SSRF", "Path Traversal"]:
        boost += 0.8

    if features["has_auth"] and module_name in ["Control de acceso", "JWT", "CSRF", "SQL Injection"]:
        boost += 0.9

    if features["has_api"] and module_name in ["API Discovery", "JWT", "Control de acceso", "SQL Injection"]:
        boost += 0.9

    if features["has_admin"] and module_name in ["Control de acceso", "Path Traversal", "SQL Injection"]:
        boost += 0.7

    if features["has_dynamic_dom"] and module_name in ["XSS DOM", "XSS reflejado"]:
        boost += 0.7

    return boost


def build_adaptive_parallel_jobs(target_url, pages, effective_pages, auth_client, scan_payload_limit):
    jobs = [
        ("XSS reflejado", scan_reflected_xss_pages, (effective_pages, scan_payload_limit)),
        ("SQL Injection", scan_sqli_pages, (effective_pages, scan_payload_limit)),
        ("Open Redirect", scan_open_redirect_pages, (effective_pages,)),
        ("JWT", scan_jwt_from_pages, (effective_pages,)),
        ("XSS DOM", scan_dom_xss, (effective_pages,)),
        ("SSTI", scan_ssti, (effective_pages,)),
        ("SSRF", scan_ssrf_hints, (effective_pages,)),
        ("Path Traversal", scan_path_traversal, (effective_pages,)),
        ("Control de acceso", scan_access_control, (target_url, pages, auth_client)),
        ("Exposición de dependencias", scan_dependency_exposure, (target_url,)),
    ]

    memory = load_memory()
    features = _extract_target_features(pages)
    ai_preferences = _collect_ai_preferences(pages)

    ranked = []
    for index, (name, func, args) in enumerate(jobs):
        ai_score = ai_preferences.get(name, 0.0)
        memory_score = _memory_module_score(memory, name)
        context_boost = _contextual_module_boost(name, features)

        score = 1.0 + (ai_score * 0.35) + (memory_score * 2.0) + context_boost
        score += max(0.0, 0.05 - (index * 0.002))

        ranked.append({
            "name": name,
            "func": func,
            "args": args,
            "score": round(score, 3),
            "ai_score": round(ai_score, 3),
            "memory_score": round(memory_score, 3),
            "context_boost": round(context_boost, 3),
        })

    ranked.sort(key=lambda item: item["score"], reverse=True)
    ordered_jobs = [(item["name"], item["func"], item["args"]) for item in ranked]
    return ordered_jobs, ranked, features


def reprioritize_for_authenticated_session(parallel_jobs, ranked_plan, auth_status):
    """When valid creds are confirmed, prioritize post-auth controls over auth-entry vectors."""
    if auth_status != "Autenticado":
        return parallel_jobs, ranked_plan

    priority_order = {
        "Control de acceso": 100,
        "JWT": 95,
        "API Discovery": 90,
        "SQL Injection": 80,
        "Path Traversal": 75,
        "SSRF": 72,
        "SSTI": 68,
        "XSS DOM": 65,
        "XSS reflejado": 62,
        "Open Redirect": 55,
        "Exposición de dependencias": 45,
    }

    reweighted = []
    for item in ranked_plan:
        module = item["name"]
        auth_bonus = priority_order.get(module, 10)
        updated = dict(item)
        updated["score"] = round(float(item.get("score", 0.0)) + auth_bonus, 3)
        updated["auth_bonus"] = auth_bonus
        reweighted.append(updated)

    reweighted.sort(key=lambda row: row["score"], reverse=True)
    reordered_jobs = []
    for row in reweighted:
        for name, func, args in parallel_jobs:
            if name == row["name"]:
                reordered_jobs.append((name, func, args))
                break

    return reordered_jobs, reweighted


def estimate_defense_pressure(module_rows):
    pressure = 0
    markers_soft = [
        "429",
        "too many requests",
        "rate limit",
        "retry-after",
        "slow down",
        "throttl",
    ]
    markers_hard = [
        "forbidden",
        "access denied",
        "waf",
        "blocked",
        "captcha",
        "challenge",
        "acceso denegado",
        "bloque",
    ]

    for row in module_rows or []:
        blob = " ".join([
            str(row.get("Resultado", "") or ""),
            str(row.get("Descripción", "") or ""),
            str(row.get("Evidencia", "") or ""),
        ]).lower()
        if any(marker in blob for marker in markers_soft):
            pressure += 1
        if any(marker in blob for marker in markers_hard):
            pressure += 2

    return min(6, pressure)


def adaptive_parallel_window(pressure, strict_mode=False):
    if pressure >= 5:
        return 1
    if pressure >= 3:
        return 2
    if pressure >= 1:
        return 3 if strict_mode else 4
    return 5 if strict_mode else 6


def build_offensive_assurance_result(all_results, aggressive_mode=False):
    required_modules = [
        "XSS reflejado",
        "SQL Injection",
        "SQL Injection Auth (Browser)",
        "Open Redirect",
        "XSS DOM",
        "SSTI",
    ]
    if aggressive_mode:
        required_modules.extend(["SSRF", "Path Traversal"])

    finding_statuses = {"Hallazgo", "Posible hallazgo"}
    incomplete_statuses = {"Error", "No probado"}

    by_module = {}
    for item in all_results:
        module = str(item.get("Módulo", ""))
        by_module.setdefault(module, []).append(item)

    modules_with_findings = []
    modules_incomplete = []
    modules_passed = []

    for module in required_modules:
        module_items = by_module.get(module, [])
        statuses = {str(x.get("Resultado", "")) for x in module_items}

        if not module_items:
            modules_incomplete.append(f"{module} (sin resultados)")
            continue

        if any(status in finding_statuses for status in statuses):
            modules_with_findings.append(module)
            continue

        if any(status in incomplete_statuses for status in statuses):
            modules_incomplete.append(module)
            continue

        modules_passed.append(module)

    if modules_with_findings:
        status = "Hallazgo"
        severity = "Alta"
        description = (
            "La validación ofensiva identificó controles vulnerables. El activo no puede etiquetarse como seguro."
        )
    elif modules_incomplete:
        status = "No probado"
        severity = "Media"
        description = (
            "No hay hallazgos en las pruebas completadas, pero la cobertura ofensiva es incompleta. "
            "No procede etiquetar el activo como seguro."
        )
    else:
        status = "No evidenciado"
        severity = "Informativa"
        description = (
            "No se evidenciaron bypasses en la batería ofensiva ejecutada con cobertura completa de módulos requeridos."
        )

    evidence = (
        f"Módulos requeridos: {len(required_modules)} | "
        f"Completados sin hallazgo: {len(modules_passed)} | "
        f"Con hallazgo: {len(modules_with_findings)} | "
        f"Incompletos: {len(modules_incomplete)} | "
        f"Pasados: {', '.join(modules_passed) if modules_passed else 'ninguno'} | "
        f"Incompletos: {', '.join(modules_incomplete) if modules_incomplete else 'ninguno'}"
    )

    recommendation = (
        "Mantener pruebas manuales de lógica de negocio y repetir en cada release."
        if not modules_with_findings and not modules_incomplete
        else "Completar módulos pendientes y repetir validación ofensiva antes de etiquetar como seguro."
    )

    return normalize_results("Aseguramiento ofensivo", [{
        "control": "Cobertura ofensiva y resistencia",
        "status": status,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }])


def _extract_result_url(item):
    evidence = str(item.get("Evidencia", "") or "")
    for token in evidence.replace("|", " ").split():
        candidate = token.strip(" ,;()[]{}<>'\"")
        if candidate.startswith("http://") or candidate.startswith("https://"):
            return candidate
    return ""


def _module_from_attack_name(name):
    normalized = _normalize_attack_name(name)
    return str(normalized or "").strip()


def _collect_expected_modules_from_ai(pages):
    expected = set()
    for page in pages or []:
        ai_context = page.get("ai_context") or {}
        for attack in ai_context.get("recommended_attacks") or []:
            module_name = _module_from_attack_name(attack.get("name"))
            if module_name:
                expected.add(module_name)
    return expected


def _evidence_strength(item):
    score = 0.0
    evidence = str(item.get("Evidencia", "") or "").lower()
    description = str(item.get("Descripción", "") or "").lower()

    if "http://" in evidence or "https://" in evidence:
        score += 0.9
    if "payload" in evidence:
        score += 0.7
    if "status" in evidence or "código" in evidence or "code" in evidence:
        score += 0.5
    if "error" in evidence and "sql" in evidence:
        score += 0.5
    if "marcador" in evidence or "marker" in evidence:
        score += 0.6
    if "posible" in description:
        score -= 0.2

    return max(0.0, score)


def _status_rank(value):
    order = {
        "hallazgo": 7,
        "posible hallazgo": 6,
        "detectado": 5,
        "comprobado": 4,
        "no evidenciado": 3,
        "no probado": 2,
        "error": 1,
    }
    return order.get(str(value or "").strip().lower(), 0)


def _severity_rank(value):
    order = {
        "crítica": 5,
        "critica": 5,
        "alta": 4,
        "media": 3,
        "baja": 2,
        "informativa": 1,
        "info": 1,
    }
    return order.get(str(value or "").strip().lower(), 0)


def _canonical_control(control):
    text = str(control or "").strip().lower()
    replacements = {
        "cabecera de seguridad ausente": "cabecera_ausente",
        "fuga de versión": "fuga_version",
        "fuga de version": "fuga_version",
        "tecnología desactualizada": "tecnologia_desactualizada",
        "tecnologia desactualizada": "tecnologia_desactualizada",
    }
    for key, token in replacements.items():
        if key in text:
            return f"{token}:{text.split(':', 1)[-1].strip()}"
    return text


def deduplicate_results(all_results):
    """Deduplicate repeated findings while preserving strongest evidence/severity."""
    grouped = {}
    order = []

    for item in all_results or []:
        current = dict(item or {})
        canonical_control = _canonical_control(current.get("Control", ""))
        url = _extract_result_url(current)
        key = f"{canonical_control}||{url}"

        if key not in grouped:
            grouped[key] = current
            order.append(key)
            continue

        existing = grouped[key]
        existing_score = (
            _status_rank(existing.get("Resultado")) * 10
            + _severity_rank(existing.get("Severidad"))
        )
        current_score = (
            _status_rank(current.get("Resultado")) * 10
            + _severity_rank(current.get("Severidad"))
        )

        # Preserve the strongest row as base and enrich evidence with source module.
        if current_score > existing_score:
            base = current
            extra = existing
        else:
            base = existing
            extra = current

        base_module = str(base.get("Módulo", "") or "")
        extra_module = str(extra.get("Módulo", "") or "")
        base_evidence = str(base.get("Evidencia", "") or "")
        extra_evidence = str(extra.get("Evidencia", "") or "")

        if extra_module and extra_module != base_module and extra_module not in base_evidence:
            base["Evidencia"] = (
                f"{base_evidence} | corroborado por módulo: {extra_module}"
                + (f" | evidencia adicional: {extra_evidence[:180]}" if extra_evidence else "")
            )

        grouped[key] = base

    deduped = [grouped[k] for k in order]
    removed = max(0, len(all_results or []) - len(deduped))

    deduped.extend(normalize_results("Control de calidad AI", [{
        "control": "Deduplicación de hallazgos",
        "status": "Comprobado",
        "severity": "Informativa",
        "description": "Se consolidaron hallazgos repetidos para reducir ruido en el informe final.",
        "evidence": f"Entradas iniciales: {len(all_results or [])} | Entradas finales: {len(deduped)} | Duplicados consolidados: {removed}",
        "recommendation": "Priorizar hallazgos consolidados con mayor severidad y evidencia corroborada.",
    }]))

    return deduped


def apply_false_positive_guard(all_results, pages, strict_mode=False):
    """
    Conservative anti-FP layer:
    - Never auto-dismiss confirmed findings.
    - Flag weak findings with explicit FP risk for manual validation.
    """
    reviewed = []
    expected_modules = _collect_expected_modules_from_ai(pages)

    by_url = {}
    by_control = {}

    for item in all_results:
        if str(item.get("Resultado", "")) not in ["Hallazgo", "Posible hallazgo"]:
            continue

        url = _extract_result_url(item)
        control = str(item.get("Control", "") or "").strip().lower()

        if url:
            by_url[url] = by_url.get(url, 0) + 1
        if control:
            by_control[control] = by_control.get(control, 0) + 1

    fp_risk_high = 0
    fp_risk_medium = 0
    strict_pending = 0

    for item in all_results:
        current = dict(item)
        status = str(current.get("Resultado", "") or "")

        if status not in ["Hallazgo", "Posible hallazgo"]:
            reviewed.append(current)
            continue

        module_name = str(current.get("Módulo", "") or "")
        module_name_l = module_name.lower()

        # Nmap findings are deterministic network observations (ports/services).
        # Do not apply offensive anti-FP severity downgrades to reconnaissance data.
        if module_name_l.startswith("nmap reconnaissance"):
            reviewed.append(current)
            continue

        url = _extract_result_url(current)
        control = str(current.get("Control", "") or "").strip().lower()

        strength = _evidence_strength(current)
        corroboration = 0.0

        if url and by_url.get(url, 0) >= 2:
            corroboration += 0.8
        if control and by_control.get(control, 0) >= 2:
            corroboration += 0.6
        if module_name in expected_modules:
            corroboration += 0.5

        confidence = strength + corroboration

        if status == "Hallazgo":
            # Guard-rail: never auto-classify confirmed findings as false positives.
            current["Evidencia"] = (
                f"{current.get('Evidencia', '')} | "
                "Control anti-FP: hallazgo confirmado conservado (sin descarte automático)."
            )
            reviewed.append(current)
            continue

        high_threshold = 1.4 if strict_mode else 1.2
        medium_threshold = 2.0 if strict_mode else 1.8

        if confidence < high_threshold:
            fp_risk_high += 1
            current["Evidencia"] = (
                f"{current.get('Evidencia', '')} | "
                "FP-RISK:ALTA (evidencia débil o aislada)."
            )
            current["Recomendación"] = (
                f"{current.get('Recomendación', '')} "
                "Validar manualmente con reproducción guiada y evidencia adicional antes de concluir."
            ).strip()
            current["Severidad"] = "Media" if current.get("Severidad") == "Alta" else current.get("Severidad", "Media")
        elif confidence < medium_threshold:
            fp_risk_medium += 1
            current["Evidencia"] = (
                f"{current.get('Evidencia', '')} | "
                "FP-RISK:MEDIA (requiere corroboración adicional)."
            )
            current["Recomendación"] = (
                f"{current.get('Recomendación', '')} "
                "Corroborar con segunda técnica o segundo vector antes de cerrar el dictamen."
            ).strip()

        if strict_mode and status == "Posible hallazgo" and confidence < 2.2:
            strict_pending += 1
            current["Evidencia"] = (
                f"{current.get('Evidencia', '')} | "
                "STRICT-REVIEW:PENDIENTE (doble corroboración recomendada)."
            )
            current["Recomendación"] = (
                f"{current.get('Recomendación', '')} "
                "En modo estricto, reproducir con un segundo vector independiente antes de elevar criticidad."
            ).strip()

        reviewed.append(current)

    reviewed.extend(normalize_results("Control de calidad AI", [{
        "control": "Filtro conservador de falsos positivos",
        "status": "Comprobado",
        "severity": "Informativa",
        "description": (
            "Se aplicó triage anti-FP sin descarte automático de hallazgos confirmados."
        ),
        "evidence": (
            f"Posibles hallazgos con FP-RISK:ALTA={fp_risk_high} | "
            f"FP-RISK:MEDIA={fp_risk_medium} | "
            f"STRICT-REVIEW:PENDIENTE={strict_pending} | "
            f"modo_estricto={bool(strict_mode)}"
        ),
        "recommendation": (
            "Revisar primero los casos FP-RISK:ALTA, luego FP-RISK:MEDIA, "
            "manteniendo trazabilidad de reproducción."
        ),
    }]))

    return reviewed


def pipeline_error_result(control, description, evidence, recommendation):
    return {
        "control": control,
        "status": "Error",
        "severity": "Alta",
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


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


def is_redirected_page(page):
    requested_url = str(page.get("url") or "").strip().rstrip("/")
    final_url = str(page.get("final_url") or requested_url).strip().rstrip("/")
    return bool(requested_url and final_url and requested_url != final_url)


def is_admin_redirect_to_auth(page):
    requested_url = str(page.get("url") or "").lower()
    final_url = str(page.get("final_url") or requested_url).lower()
    classification = str(page.get("classification", "")).lower()

    if not is_redirected_page(page):
        return False

    if classification == "protected_redirect_to_auth":
        return True

    admin_tokens = ["/admin", "dashboard", "panel", "backoffice", "administrator"]
    auth_tokens = ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion"]

    return any(token in requested_url for token in admin_tokens) and any(token in final_url for token in auth_tokens)


def is_auth_like_page(page):
    url = str(page.get("final_url") or page.get("url") or "").lower()
    classification = str(page.get("classification", "")).lower()
    auth_tokens = ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion", "register", "registro", "signup"]
    return (
        classification in ["auth", "registration"]
        or has_auth_form_indicators(page)
        or any(token in url for token in auth_tokens)
    )


def is_auth_attack_page(page):
    url = str(page.get("final_url") or page.get("url") or "").lower()
    classification = str(page.get("classification", "")).lower()

    if is_blocked_or_error_page(page):
        return False

    if is_admin_redirect_to_auth(page):
        return False

    return (
        classification == "auth"
        or "login" in url
        or "signin" in url
        or "iniciar-sesion" in url
        or "inicio-sesion" in url
    )


def has_auth_form_indicators(page):
    forms = page.get("forms") or []
    runtime_inputs = page.get("browser_inputs") or (page.get("browser_runtime") or {}).get("inputs") or []

    flattened_forms = str(forms).lower()
    flattened_runtime = str(runtime_inputs).lower()
    combined = f"{flattened_forms} {flattened_runtime}"

    has_password = "password" in combined or "contraseña" in combined
    has_user = any(token in combined for token in ["email", "correo", "usuario", "user", "login"])
    return has_password and has_user


def build_auth_attack_pages(pages):
    auth_keywords = ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion", "session"]
    candidates = []
    seen = set()

    for page in pages or []:
        url = str(page.get("final_url") or page.get("url") or "").lower()
        classification = str(page.get("classification", "")).lower()
        ai_page_type = str((page.get("ai_context") or {}).get("page_type", "")).lower()

        if is_admin_redirect_to_auth(page):
            continue

        # Keep admin candidates out of auth SQLi target set; they are tested in access control.
        if classification == "admin_candidate":
            continue

        is_candidate = (
            is_auth_attack_page(page)
            or has_auth_form_indicators(page)
            or ai_page_type == "auth"
            or any(keyword in url for keyword in auth_keywords)
        )

        if not is_candidate:
            continue

        key = str(page.get("final_url") or page.get("url") or "")
        if key and key not in seen:
            seen.add(key)
            candidates.append(page)

    return candidates


def is_generic_attack_page(page):
    if is_admin_redirect_to_auth(page):
        return False

    # Login/registration with credentials fields must be attackable even if page text contains generic blockers.
    classification = str(page.get("classification", "")).lower()
    if classification in ["auth", "registration"] and has_auth_form_indicators(page):
        return True

    if is_blocked_or_error_page(page):
        return False

    status = str(page.get("status_code", ""))

    if is_redirected_page(page) and not is_auth_like_page(page):
        return False

    # Treat pages with no status_code as accessible (URL harvested from HTML, not direct request)
    if not status:
        return True

    # Accept 2xx and 3xx; exclude 4xx/5xx (except 401/403 which may still have forms)
    if status.startswith("2") or status.startswith("3"):
        return True

    # 401/403 pages may expose forms behind auth — still worth probing
    if status in ("401", "403"):
        return bool(page.get("forms"))

    return False


def dedupe_pages_by_url(pages):
    best_pages = {}
    order = []

    for page in pages or []:
        key = _canonical_surface_url(page.get("final_url") or page.get("url"))
        if not key:
            continue

        if key not in best_pages:
            best_pages[key] = page
            order.append(key)
            continue

        current = best_pages[key]
        if _page_quality_score(page) > _page_quality_score(current):
            best_pages[key] = page

    return [best_pages[k] for k in order]


def _is_noise_surface_url(url):
    parsed = urlparse(str(url or "").strip())
    path = (parsed.path or "").strip().lower()
    if not path:
        return False

    if path in {"/&", "/#", "/?", "/undefined", "/null", "/none"}:
        return True

    segments = [segment for segment in path.split("/") if segment]
    if len(segments) == 1 and all(ch in "&#?;,:" for ch in segments[0]):
        return True

    return False


def _canonical_surface_url(raw_url):
    url = str(raw_url or "").strip()
    if not url:
        return ""

    if _is_noise_surface_url(url):
        return ""

    clean = url.split("#", 1)[0].strip().rstrip("/")
    return clean


def _safe_status_int(value):
    try:
        return int(value)
    except Exception:
        return 0


def _page_quality_score(page):
    status = _safe_status_int(page.get("status_code"))
    classification = str(page.get("classification", "")).lower()

    score = 0
    if 200 <= status < 400:
        score += 6
    elif status in (401, 403):
        score += 5
    elif status >= 500:
        score += 1

    if classification in {
        "protected",
        "protected_redirect_to_auth",
        "admin_candidate",
        "api_candidate",
        "sensitive_candidate",
        "auth",
        "registration",
    }:
        score += 3

    if str(page.get("discovery_context", "")).lower() == "post_login":
        score += 1

    if page.get("is_new_post_login"):
        score += 1

    return score


def _is_meaningful_post_login_page(page):
    url = page.get("final_url") or page.get("url") or ""
    if not _canonical_surface_url(url):
        return False

    status = _safe_status_int(page.get("status_code"))
    if status == 404 or status == 0:
        return False

    classification = str(page.get("classification", "")).lower()
    if classification in {"soft_404", "request_error", "html_candidate"}:
        return False

    return True


def _discovered_entry_url(entry):
    if isinstance(entry, dict):
        return str(
            entry.get("final_url")
            or entry.get("requested_url")
            or entry.get("url")
            or ""
        ).strip().rstrip("/")
    return str(entry or "").strip().rstrip("/")


def _normalize_discovered_entry(entry):
    if isinstance(entry, dict):
        normalized = dict(entry)
        normalized["requested_url"] = str(normalized.get("requested_url") or normalized.get("url") or "")
        normalized["final_url"] = str(normalized.get("final_url") or normalized.get("requested_url") or normalized.get("url") or "")
        normalized["url"] = str(normalized.get("url") or normalized.get("final_url") or normalized.get("requested_url") or "")
        if not _canonical_surface_url(normalized.get("final_url") or normalized.get("requested_url") or normalized.get("url")):
            return None
        return normalized

    url = _discovered_entry_url(entry)
    url = _canonical_surface_url(url)
    if not url:
        return None

    return {
        "source": "unknown",
        "requested_url": url,
        "final_url": url,
        "url": url,
        "status_code": "",
        "classification": "",
        "observation": "",
    }


def merge_discovered_entries(*collections):
    merged = []
    seen = set()

    for collection in collections:
        for entry in collection or []:
            normalized_entry = _normalize_discovered_entry(entry)
            if not normalized_entry:
                continue
            url = _canonical_surface_url(_discovered_entry_url(entry))
            if not url or url in seen:
                continue
            seen.add(url)
            merged.append(normalized_entry)

    return merged


def discovered_entries_to_urls(entries):
    urls = []
    seen = set()

    for entry in entries or []:
        url = _canonical_surface_url(_discovered_entry_url(entry))
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)

    return urls


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


def _compute_discovery_active_checks(is_aggressive_mode, seed_pages_count):
    base = 500 if is_aggressive_mode else 300
    adaptive = base + min(max(int(seed_pages_count or 0), 0), 600)
    return max(250, min(adaptive, 1200))


def _compute_external_target_limit(scan_mode, hosts_count, is_aggressive_mode):
    if int(hosts_count or 0) <= 0:
        return 0
    mode = str(scan_mode or "").lower()
    if "deep" in mode or "offensive" in mode:
        base = 10
    elif is_aggressive_mode:
        base = 8
    else:
        base = 5
    return max(3, min(base, int(hosts_count or 0)))


def _compute_free_scanner_target_limit(scan_mode, hosts_count, depth):
    if int(hosts_count or 0) <= 0:
        return 0
    mode = str(scan_mode or "").lower()
    depth = str(depth or "").lower()
    base = 7 if "completo" in depth else 5
    if "deep" in mode or "offensive" in mode:
        base += 3
    return max(2, min(base, int(hosts_count or 0)))


def _severity_from_cvss(score):
    try:
        value = float(score or 0)
    except Exception:
        value = 0.0
    if value >= 9.0:
        return "Crítica"
    if value >= 7.0:
        return "Alta"
    if value >= 4.0:
        return "Media"
    if value > 0:
        return "Baja"
    return "Informativa"


def _collect_cves_from_nessus_structured(nessus_structured):
    cves = []
    for vuln in (nessus_structured or {}).get("vulnerabilities") or []:
        raw_cve = vuln.get("cve")
        cvss = vuln.get("cvss")
        plugin = str(vuln.get("plugin_name") or "Nessus plugin")
        service = str(vuln.get("software") or "")

        if isinstance(raw_cve, list):
            candidates = raw_cve
        else:
            candidates = str(raw_cve or "").replace(";", ",").split(",")

        for token in candidates:
            cve_id = str(token or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            cves.append({
                "id": cve_id,
                "score": float(cvss or 0) if str(cvss or "").strip() else 0,
                "severity": str(vuln.get("severity") or ""),
                "description": plugin,
                "service": service,
                "source": "nessus",
            })
    return cves


def _collect_nmap_service_cves(nmap_structured, *, max_services=8, max_cves_per_service=4):
    """Query CVE intel for service/version pairs detected by Nmap."""
    hosts = (nmap_structured or {}).get("hosts") or []
    if not hosts:
        return [], []

    services = []
    seen = set()
    for host in hosts:
        host_ip = str(host.get("host") or "")
        for p in host.get("ports") or []:
            if str(p.get("state") or "").lower() != "open":
                continue
            service = str(p.get("product") or p.get("service") or "").strip()
            version = str(p.get("version") or "").strip()
            if not service:
                continue
            key = f"{service.lower()}::{version.lower()}"
            if key in seen:
                continue
            seen.add(key)
            services.append({
                "host": host_ip,
                "port": p.get("port"),
                "protocol": p.get("protocol"),
                "service": service,
                "version": version,
            })

    services = services[:max_services]
    if not services:
        return [], []

    lookup = CVELookup(timeout=6.0)
    rows = []
    cves_flat = []

    for svc in services:
        try:
            found = lookup.search_cves(svc["service"], svc["version"])
        except Exception:
            found = []

        if not found:
            continue

        top = sorted(
            found,
            key=lambda x: float(x.get("score", 0) or 0),
            reverse=True,
        )[:max_cves_per_service]

        for cve in top:
            score = float(cve.get("score", 0) or 0)
            cve_id = str(cve.get("id") or "").upper()
            rows.append({
                "control": f"CVE correlacionado por versión: {cve_id}",
                "status": "Posible hallazgo" if score >= 4 else "Detectado",
                "severity": _severity_from_cvss(score),
                "description": (
                    f"Servicio/version detectado por Nmap coincide con vulnerabilidad conocida: "
                    f"{svc['service']} {svc['version'] or '(sin versión)'}"
                ),
                "evidence": (
                    f"Host: {svc['host']} | Puerto: {svc['port']}/{svc['protocol']} | "
                    f"Servicio: {svc['service']} | Versión: {svc['version'] or '-'} | "
                    f"CVE: {cve_id} | CVSS: {score}"
                ),
                "recommendation": "Validar explotación en entorno controlado y aplicar parche/mitigación prioritaria.",
            })
            cves_flat.append({
                "id": cve_id,
                "score": score,
                "severity": cve.get("severity") or "",
                "description": cve.get("description") or "",
                "service": svc["service"],
                "version": svc["version"],
                "source": "nmap-cve-correlation",
            })

    if rows:
        rows.append({
            "control": "Correlación CVE por servicios Nmap",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Se correlacionaron servicios/versiones abiertos con bases CVE públicas.",
            "evidence": f"Servicios analizados: {len(services)} | CVEs correlacionados: {len(cves_flat)}",
            "recommendation": "Priorizar CVEs con CVSS>=7 y exposición directa a Internet.",
        })

    return rows, cves_flat


def build_attack_path_intel(*, all_results, discovered_urls, cves):
    """Create practical attack-path summaries from discovered assets and vulnerabilities."""
    ip_regex = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    hosts = set()
    service_hits = 0
    enum_findings = 0
    api_signals = 0

    for row in all_results or []:
        module = str(row.get("Módulo") or "")
        status = str(row.get("Resultado") or "")
        evidence = str(row.get("Evidencia") or "")
        control = str(row.get("Control") or "").lower()

        for ip in ip_regex.findall(evidence):
            hosts.add(ip)

        if module == "Nmap reconnaissance" and "servicio expuesto" in control:
            service_hits += 1

        if module == "Enumeración de usuarios" and status in {"Hallazgo", "Posible hallazgo"}:
            enum_findings += 1

        if module == "API Discovery" and status in {"Detectado", "Hallazgo", "Posible hallazgo"}:
            api_signals += 1

    high_cves = [
        c for c in (cves or [])
        if float(c.get("score", 0) or 0) >= 7.0
    ]

    rows = []
    if hosts and service_hits:
        rows.append({
            "control": "Cadena de ataque: infraestructura expuesta",
            "status": "Detectado",
            "severity": "Alta" if high_cves else "Media",
            "description": (
                "Se detectó superficie de infraestructura explotable: hosts/IP con servicios/versiones expuestos."
            ),
            "evidence": (
                f"Hosts/IP detectados: {len(hosts)} | Servicios expuestos: {service_hits} | "
                f"CVEs altas/críticas correlacionadas: {len(high_cves)}"
            ),
            "recommendation": (
                "Priorizar endurecimiento de servicios expuestos, segmentación de red y parcheo de CVEs CVSS>=7."
            ),
        })

    if discovered_urls and api_signals:
        rows.append({
            "control": "Cadena de ataque: endpoints y APIs",
            "status": "Detectado",
            "severity": "Media",
            "description": "La enumeración de endpoints/API abre rutas de acceso a datos y lógica de negocio sensible.",
            "evidence": (
                f"URLs descubiertas: {len(discovered_urls)} | Señales API: {api_signals}"
            ),
            "recommendation": "Validar authN/authZ por endpoint, rate limiting y exposición de datos sensibles.",
        })

    if enum_findings > 0:
        rows.append({
            "control": "Cadena de ataque: enumeración de usuarios",
            "status": "Posible hallazgo",
            "severity": "Media",
            "description": "Se observaron diferencias de respuesta compatibles con enumeración de usuarios.",
            "evidence": f"Controles con señal de enumeración: {enum_findings}",
            "recommendation": "Uniformar respuestas de autenticación y reforzar lockout/rate-limit por identidad/IP.",
        })

    if high_cves:
        sample = ", ".join([str(c.get("id")) for c in high_cves[:5]])
        rows.append({
            "control": "Priorización de explotación por CVE",
            "status": "Detectado",
            "severity": "Alta",
            "description": "Se identificaron CVEs con prioridad de validación de explotación en entorno controlado.",
            "evidence": f"CVEs CVSS>=7: {len(high_cves)} | Muestra: {sample}",
            "recommendation": "Validar exploitabilidad real, impacto y alcance antes de remediación final.",
        })

    if not rows:
        rows.append({
            "control": "Cadena de ataque",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se reunió evidencia suficiente para construir una cadena de ataque completa.",
            "evidence": "Superficie o correlación insuficiente en esta ejecución.",
            "recommendation": "Ampliar alcance autenticado y escaneo de infraestructura para mejorar la correlación.",
        })

    return rows


def _scan_phase1(
    target_url,
    scan_mode,
    verify_ssl,
    use_burp_proxy,
    burp_proxy_url,
    use_auth,
    login_url,
    username,
    password,
    max_auth_sqli_payloads,
    audit_name,
    strict_fp_mode,
    enable_nmap,
    nmap_profile,
    include_udp,
    nmap_timeout_seconds,
    nmap_scripts,
    enable_nessus,
    nessus_mode,
    nessus_base_url,
    nessus_access_key,
    nessus_secret_key,
    nessus_verify_ssl,
    nessus_poll_seconds,
    nessus_template_uuid,
    nmap_bin: str | None = None,
):
    """Phase 1: crawl, discovery, passive recon. Returns session state dict."""
    all_results = []
    scan_profile = SCAN_MODES.get(scan_mode, {})
    scan_delay = float(scan_profile.get("delay", 0.35))
    scan_payload_limit = scan_profile.get("max_payloads")
    is_aggressive_mode = bool(scan_profile.get("aggressive", False))
    port_scan_profile = str(scan_profile.get("port_scan_profile", "common"))
    vuln_corr_profile = str(scan_profile.get("vuln_correlation_profile", "standard"))
    effective_auth_payload_limit = resolve_payload_limit(scan_payload_limit, max_auth_sqli_payloads)
    effective_proxy_url = burp_proxy_url.strip() if use_burp_proxy else None

    # Phase 1: Desabilitar SSL verification para módulos pasivos
    # Los módulos de reconnaissance (headers, cookies, CORS, etc.) no requieren SSL strict
    # porque no realizan pruebas ofensivas. Esto evita errores con certificados autofirmados.
    _configure_http_defaults_compat(delay=scan_delay, verify_ssl=False, proxy_url=effective_proxy_url)
    auth_client = HttpClient(verify_ssl=False)
    auth_status = "No configurado"
    auth_used_login_url = ""
    auth_final_url = ""
    auth_cookies = {}

    st.markdown(
        f"""
        <div class="bh-panel">
            <b>Fase 1 — Reconocimiento y mapeo de superficie</b><br>
            Objetivo: <b>{html.escape(str(target_url))}</b> | Modo: <b>{html.escape(str(scan_mode))}</b><br>
            Proxy Burp: <b>{html.escape(effective_proxy_url if effective_proxy_url else 'desactivado')}</b>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.spinner("Crawling completo del objetivo..."):
        try:
            crawler_pages, _ssl_fallback = crawl_site(target_url, max_pages=None, client=auth_client)
            if _ssl_fallback:
                st.info("⚠️ El certificado SSL del objetivo no pudo verificarse. La herramienta continuó el crawl omitiendo la verificación SSL (comportamiento esperado en entornos con certificados autofirmados o internos).")
        except Exception:
            crawler_pages = []
            _ssl_fallback = False
            all_results.extend(normalize_results("Crawler", [pipeline_error_result(
                control="Crawler",
                description="Error durante el crawling inicial.",
                evidence=traceback.format_exc(),
                recommendation="Revisar conectividad, DNS, certificados SSL/TLS y bloqueos WAF.",
            )]))

    with st.spinner("Discovery activo con diccionario de rutas comunes..."):
        try:
            active_checks_budget = _compute_discovery_active_checks(
                is_aggressive_mode=is_aggressive_mode,
                seed_pages_count=len(crawler_pages or []),
            )
            discovery = discover_surface(
                target_url,
                client=auth_client,
                seed_pages=crawler_pages,
                max_active_checks=active_checks_budget,
            )
        except Exception:
            discovery = {
                "pages": list(crawler_pages),
                "discovered": [],
                "results": [pipeline_error_result(
                    control="Discovery",
                    description="Error durante discovery activo; se usa superficie previa de crawler.",
                    evidence=traceback.format_exc(),
                    recommendation="Validar estabilidad del objetivo, límites de rate-limit y errores SSL.",
                )],
                "metrics": {},
            }

    pages = discovery.get("pages") or []
    if not pages and crawler_pages:
        pages = crawler_pages
        st.warning("Discovery activo no devolvió páginas útiles. Se continúa con la superficie del crawler.")

    # Safe, low-noise user enumeration before trying provided credentials.
    enum_results = scan_user_enumeration(
        pages=pages,
        client=auth_client,
        username_hint=username if use_auth else "",
    )
    all_results.extend(normalize_results("Enumeración de usuarios", enum_results))

    # Auth flow after initial mapping: discover first, then try credentials, then expand scope post-login.
    if use_auth and username and password:
        effective_login_url = (login_url or "").strip()

        if not effective_login_url:
            st.info("No se indicó URL de login. Intentando autodetección sobre la superficie descubierta...")
            detected_login_url, autodetect_result = _auto_detect_login_url(target_url, auth_client)
            all_results.extend(normalize_results("Autenticación", [autodetect_result]))
            if detected_login_url:
                effective_login_url = detected_login_url
                st.info(f"URL de login detectada automáticamente: {detected_login_url}")

        login_candidates = _collect_login_candidates(target_url, pages, manual_login_url=effective_login_url)

        st.info(f"Probando credenciales en {len(login_candidates)} endpoint(s) de login detectados...")
        chosen_indeterminate_client = None
        chosen_indeterminate_url = ""

        for candidate in login_candidates:
            attempt_client, attempt_results = authenticate(
                candidate,
                username,
                password,
                verify_ssl=verify_ssl,
            )
            attempt_client.verify_ssl = verify_ssl
            all_results.extend(normalize_results("Autenticación", attempt_results))

            status = str((attempt_results or [{}])[0].get("status", "")).strip()
            attempt_final_url = str((attempt_results or [{}])[0].get("final_url", "")).strip()
            if status:
                auth_status = status
                auth_used_login_url = candidate
            if attempt_final_url:
                auth_final_url = attempt_final_url
            if status == "Autenticado":
                auth_client = attempt_client
                auth_status = status
                auth_used_login_url = candidate
                if attempt_final_url:
                    auth_final_url = attempt_final_url
                break

            if status == "Indeterminado" and not chosen_indeterminate_client:
                chosen_indeterminate_client = attempt_client
                chosen_indeterminate_url = candidate

        if auth_status != "Autenticado" and chosen_indeterminate_client is not None:
            auth_client = chosen_indeterminate_client
            auth_status = "Indeterminado"
            auth_used_login_url = chosen_indeterminate_url

        # If auth appears successful (or plausible), run post-auth crawl/discovery to expand protected scope.
        if auth_status in ["Autenticado", "Indeterminado"]:
            with st.spinner("Sesión establecida. Ejecutando recrawl post-login para descubrir superficie autenticada..."):
                try:
                    pre_auth_surface_keys = {
                        _canonical_surface_url(page.get("final_url") or page.get("url"))
                        for page in (pages or [])
                    }
                    pre_auth_surface_keys.discard("")

                    post_auth_pages, _ = crawl_site(target_url, max_pages=None, client=auth_client)
                    for page in post_auth_pages or []:
                        page["discovery_context"] = "post_login"
                        page_key = _canonical_surface_url(page.get("final_url") or page.get("url"))
                        page["is_new_post_login"] = bool(page_key and page_key not in pre_auth_surface_keys)

                    # Probe authenticated-only hint routes that crawlers miss due to JS rendering.
                    _auth_hint_paths = [
                        "/es/usuario", "/usuario", "/en/user", "/user",
                        "/es/restaurantes", "/restaurantes",
                        "/es/panel-usuario", "/panel-usuario",
                        "/es/panel-restaurante", "/panel-restaurante",
                        "/es/restauranteAdministracion", "/restauranteAdministracion",
                        "/es/cuenta", "/cuenta", "/es/perfil", "/perfil",
                        "/es/dashboard", "/dashboard",
                        "/es/admin", "/admin",
                        "/es/backoffice", "/backoffice",
                        "/es/mis-restaurantes", "/mis-restaurantes",
                    ]
                    _parsed_origin = urlparse(target_url)
                    _origin_base = f"{_parsed_origin.scheme}://{_parsed_origin.netloc}"
                    _existing_post_keys = {
                        _canonical_surface_url(p.get("final_url") or p.get("url"))
                        for p in post_auth_pages
                    }
                    for _hint_path in _auth_hint_paths:
                        _hint_url = _origin_base + _hint_path
                        _hint_key = _canonical_surface_url(_hint_url)
                        if _hint_key in pre_auth_surface_keys or _hint_key in _existing_post_keys:
                            continue
                        try:
                            _hint_resp = auth_client.get(_hint_url)
                            _hint_status = int(getattr(_hint_resp, "status_code", 0) or 0)
                            _hint_final = _canonical_surface_url(str(_hint_resp.url or _hint_url))
                            if _hint_status == 404:
                                continue
                            _hint_html = _hint_resp.text or ""
                            _is_actually_new = _hint_final not in pre_auth_surface_keys
                            post_auth_pages.append({
                                "url": _hint_url,
                                "final_url": str(_hint_resp.url or _hint_url),
                                "status_code": _hint_status,
                                "content_type": _hint_resp.headers.get("Content-Type", ""),
                                "html": _hint_html,
                                "forms": [],
                                "classification": "protected" if _hint_status in (200, 301, 302, 403) else "html_candidate",
                                "discovery_context": "post_login",
                                "is_new_post_login": _is_actually_new,
                            })
                            _existing_post_keys.add(_hint_final)
                        except Exception:
                            pass

                    if auth_final_url:
                        landing_key = _canonical_surface_url(auth_final_url)
                        known_post_keys = {
                            _canonical_surface_url(page.get("final_url") or page.get("url"))
                            for page in (post_auth_pages or [])
                        }
                        if landing_key and landing_key not in known_post_keys:
                            try:
                                landing_response = auth_client.get(auth_final_url)
                                landing_html = landing_response.text or ""
                                landing_content_type = landing_response.headers.get("Content-Type", "")
                                if (
                                    "text/html" in str(landing_content_type).lower()
                                    or "<html" in landing_html[:5000].lower()
                                ):
                                    post_auth_pages.append({
                                        "url": auth_final_url,
                                        "final_url": str(landing_response.url or auth_final_url),
                                        "status_code": int(getattr(landing_response, "status_code", 0) or 0),
                                        "content_type": landing_content_type,
                                        "html": landing_html,
                                        "forms": [],
                                        "classification": "protected",
                                        "discovery_context": "post_login",
                                        "is_new_post_login": True,
                                    })
                            except Exception:
                                pass

                    merged_seed = dedupe_pages_by_url((pages or []) + (post_auth_pages or []))
                    post_auth_discovery = discover_surface(
                        target_url,
                        client=auth_client,
                        seed_pages=merged_seed,
                        max_active_checks=_compute_discovery_active_checks(
                            is_aggressive_mode=is_aggressive_mode,
                            seed_pages_count=len(merged_seed or []),
                        ),
                    )

                    post_pages = post_auth_discovery.get("pages") or []
                    for page in post_pages:
                        page["discovery_context"] = "post_login"
                        page_key = _canonical_surface_url(page.get("final_url") or page.get("url"))
                        page["is_new_post_login"] = bool(page_key and page_key not in pre_auth_surface_keys)

                    pages = dedupe_pages_by_url(merged_seed + post_pages)

                    combined_discovered = merge_discovered_entries(
                        discovery.get("discovered") or [],
                        post_auth_discovery.get("discovered") or [],
                    )
                    discovery["discovered"] = combined_discovered

                    post_results = post_auth_discovery.get("results") or []
                    if post_results:
                        all_results.extend(normalize_results("Discovery post-login", post_results))

                    protected_hint_tokens = ["admin", "dashboard", "backoffice", "private", "restauranteadministracion"]
                    protected_classifications = {
                        "protected",
                        "admin_candidate",
                        "api_candidate",
                        "sensitive_candidate",
                    }
                    post_login_surface = [
                        page for page in pages
                        if str(page.get("discovery_context", "")).lower() == "post_login"
                        and _is_meaningful_post_login_page(page)
                    ]
                    protected_post_login = [
                        page for page in post_login_surface
                        if str(page.get("classification", "")).lower() in protected_classifications
                        or any(
                            token in str(page.get("final_url") or page.get("url") or "").lower()
                            for token in protected_hint_tokens
                        )
                    ]
                    protected_samples = [
                        str(page.get("final_url") or page.get("url") or "")
                        for page in protected_post_login[:6]
                    ]
                    session_cookie_names = sorted(dict_from_cookiejar(auth_client.session.cookies).keys())

                    all_results.extend(normalize_results("Autenticación", [{
                        "control": "Cobertura post-login",
                        "status": "Detectado",
                        "severity": "Informativa",
                        "description": "Se amplió superficie tras autenticación para descubrir rutas protegidas.",
                        "evidence": (
                            f"Login usado: {auth_used_login_url or 'autodetectado'} | "
                            f"URL final auth: {auth_final_url or 'no detectada'} | "
                            f"URLs post-login: {len(post_login_surface)} | "
                            f"Rutas protegidas detectadas: {len(protected_post_login)} | "
                            f"Cookies de sesión: {', '.join(session_cookie_names[:6]) if session_cookie_names else 'ninguna'} | "
                            f"Muestras: {' | '.join(protected_samples) if protected_samples else 'sin muestras'}"
                        ),
                        "recommendation": "Priorizar revisión de rutas administrativas descubiertas en sesión autenticada.",
                    }]))
                except Exception:
                    all_results.extend(normalize_results("Autenticación", [pipeline_error_result(
                        control="Cobertura post-login",
                        description="No se pudo completar el recrawl/discovery post-login.",
                        evidence=traceback.format_exc(),
                        recommendation="Validar vigencia de sesión, redirecciones y defensas anti-bot en login.",
                    )]))

        try:
            auth_cookies = dict(dict_from_cookiejar(auth_client.session.cookies))
        except Exception:
            auth_cookies = {}
    elif use_auth:
        all_results.extend(normalize_results("Autenticación", [{
            "control": "Autenticación",
            "status": "No configurado",
            "severity": "Informativa",
            "description": "Se activó login, pero faltan usuario/contraseña para probar credenciales.",
            "evidence": f"login_url={login_url or 'autodetect'} | username={'sí' if username else 'no'} | password={'sí' if password else 'no'}",
            "recommendation": "Completar credenciales para habilitar descubrimiento post-login y cobertura autenticada.",
        }]))

    try:
        pages = enrich_pages_with_ai_context(pages)
    except Exception:
        all_results.extend(normalize_results("Enriquecimiento AI", [pipeline_error_result(
            control="Enriquecimiento AI",
            description="Error en enriquecimiento AI; se continúa sin este paso.",
            evidence=traceback.format_exc(),
            recommendation="Revisar dependencias del agente AI.",
        )]))

    discovered_urls = discovered_entries_to_urls(discovery.get("discovered") or [])

    runtime_candidates = [
        page for page in pages
        if page.get("ai_context", {}).get("page_type") == "auth"
        or page.get("ai_context", {}).get("requires_browser_dom")
        or is_auth_like_page(page)
    ]

    if runtime_candidates:
        st.info(f"Analizando DOM dinámico en {len(runtime_candidates)} URL(s)...")
        dom_progress = st.progress(0)
        dom_status_box = st.empty()

        for index, page in enumerate(runtime_candidates, start=1):
            page_url = page.get("final_url") or page.get("url")
            if not page_url:
                continue
            dom_status_box.write(f"Renderizando con Playwright: {page_url}")
            runtime = _extract_auth_runtime_evidence_safe(page_url, headless=True, timeout_ms=8000)
            add_browser_runtime_form_if_detected(page, runtime)
            dom_progress.progress(index / len(runtime_candidates))

        dom_status_box.write("Análisis DOM finalizado.")

    all_results.extend(normalize_results("Discovery", discovery.get("results") or []))
    all_results.extend(run_module("Mapeando URLs asociadas...", "Mapa de URLs", map_urls, target_url, pages, auth_client))
    all_results.extend(run_module("Reconocimiento tecnológico...", "Reconocimiento", scan_recon, target_url))
    all_results.extend(run_module("Resolviendo IP/DNS y exposición de versión...", "Red e infraestructura", network_recon.scan_network_recon, target_url))
    all_results.extend(run_module("Escaneando puertos/servicios comunes...", "Puertos y servicios", scan_port_services, target_url, port_scan_profile))
    all_results.extend(run_module("Correlando exposición tecnológica (Nessus-like)...", "Correlación de vulnerabilidades", scan_vulnerability_correlation, target_url, vuln_corr_profile))

    # ── Advanced external recon (Nmap + Nessus/Tenable) ─────────────────
    external_targets = collect_external_scan_targets(
        target_url=target_url,
        pages=pages,
        discovery=discovery,
        results=all_results,
    )

    nmap_structured = {"hosts": []}
    external_hosts = external_targets.get("hosts", [])
    candidate_targets = []
    external_target_limit = _compute_external_target_limit(
        scan_mode=scan_mode,
        hosts_count=len(external_hosts),
        is_aggressive_mode=is_aggressive_mode,
    )

    if not external_hosts:
        all_results.extend(normalize_results("Correlación IA ofensiva", [{
            "control": "Targets externos",
            "status": "No detectado",
            "severity": "Informativa",
            "description": "No se detectaron hosts/IP externos adicionales para escaneo de infraestructura.",
            "evidence": "collect_external_scan_targets devolvió lista vacía.",
            "recommendation": "Mantener análisis web y ampliar discovery de subdominios/activos cuando corresponda.",
        }]))

    if enable_nmap and external_target_limit > 0:
        import queue as _queue
        _nmap_queue: _queue.SimpleQueue = _queue.SimpleQueue()
        nmap_status = st.empty()

        def nmap_progress(event):
            # Called from background reader thread — NEVER touch Streamlit UI here.
            # Accumulate into a thread-safe queue; drained after run_nmap_recon returns.
            try:
                _nmap_queue.put_nowait(event)
            except Exception:
                pass

        with st.spinner("Ejecutando Nmap avanzado..."):
            nmap_rows, nmap_structured = run_nmap_recon(
                targets=external_hosts[:external_target_limit],
                profile=nmap_profile,
                               nmap_path=nmap_bin,
                timeout_seconds=int(nmap_timeout_seconds or 420),
                include_udp=bool(include_udp),
                custom_scripts=str(nmap_scripts or "").strip(),
                progress_callback=nmap_progress,
            )
        all_results.extend(normalize_results("Nmap reconnaissance", nmap_rows))

        parity_enabled = bool(st.session_state.get("_parity_nmap_nessus", False))
        if parity_enabled or str(nmap_profile or "").upper() in {"DEEP", "AGGRESSIVE"}:
            with st.spinner("Correlando CVEs por servicios/versiones detectados por Nmap..."):
                nmap_cve_rows, nmap_cves = _collect_nmap_service_cves(
                    nmap_structured,
                    max_services=10 if parity_enabled else 6,
                    max_cves_per_service=4,
                )
            if nmap_cve_rows:
                all_results.extend(normalize_results("Correlación CVE (Nmap)", nmap_cve_rows))
            if nmap_cves:
                _all_cves_found.extend(nmap_cves)

        # Drain progress queue and show last meaningful event in UI (safe — main thread).
        last_event: dict | None = None
        while not _nmap_queue.empty():
            try:
                last_event = _nmap_queue.get_nowait()
            except Exception:
                break
        if last_event:
            _nmap_host = str(last_event.get("host", "") or "-")
            _nmap_detail = str(last_event.get("detail", "") or last_event.get("stage", "completado"))
            nmap_status.markdown(
                f"[NMAP] Completado | Último host: {_nmap_host} | Detalle: {_nmap_detail[:120]}"
            )

    nessus_structured = {"scan_id": None, "vulnerabilities": []}
    _all_cves_found: list = []  # flat CVE list for exploit suggester
    
    # Execute vulnerability scanning (Nessus or Free Scanner)
    if enable_nessus and external_target_limit > 0:
        nessus_status = st.empty()

        def nessus_progress(event):
            stage = str(event.get("stage", "nessus"))
            scan_id = str(event.get("scan_id", ""))
            progress = str(event.get("progress", ""))
            detail = str(event.get("detail", ""))
            nessus_status.markdown(
                "[NESSUS]  "
                f"Scan ID: {scan_id or '-'} | "
                f"Progreso: {progress or '-'} | "
                f"Plugin/CVE: - | CVSS: - | "
                f"Detalle: {detail[:100] if detail else stage}"
            )

        cfg = NessusConfig(
            mode=str(nessus_mode or "nessus-local"),
            base_url=str(nessus_base_url or "https://localhost:8834").strip(),
            access_key=str(nessus_access_key or "").strip(),
            secret_key=str(nessus_secret_key or "").strip(),
            verify_ssl=bool(nessus_verify_ssl),
            poll_interval_seconds=6,
            max_poll_seconds=int(nessus_poll_seconds or 180),
            scan_name=f"{audit_name} - BH Sentinel",
            template_uuid=str(nessus_template_uuid or "basic").strip(),
        )

        with st.spinner("Ejecutando Nessus/Tenable..."):
            nessus_rows, nessus_structured = run_nessus_assessment(
                targets=external_hosts[:external_target_limit],
                cfg=cfg,
                progress_callback=nessus_progress,
            )
        all_results.extend(normalize_results("Nessus/Tenable", nessus_rows))
        _all_cves_found.extend(_collect_cves_from_nessus_structured(nessus_structured))
    
    if use_free_scanner:
        free_status = st.empty()
        
        def free_scanner_progress(msg, progress_pct):
            free_status.markdown(f"[BlackHarrier SCANNER] {msg} ({progress_pct}%)")
        
        free_assessment = FreeAssessment(timeout=5.0, max_workers=50)
        
        # Determine scan type based on user selection
        port_type = "tcp" if free_scanner_depth == "Rápido" else "both"
        
        with st.spinner("Ejecutando escaneo de vulnerabilidades..."):
            try:
                # Scan external targets
                free_target_limit = _compute_free_scanner_target_limit(
                    scan_mode=scan_mode,
                    hosts_count=len(external_hosts),
                    depth=free_scanner_depth,
                )
                targets_to_scan = external_hosts[:free_target_limit]

                if not targets_to_scan:
                    all_results.extend(normalize_results("BlackHarrier Scanner", [{
                        "control": "BlackHarrier Scanner",
                        "status": "No probado",
                        "severity": "Informativa",
                        "description": "No hay hosts externos disponibles para escaneo de red.",
                        "evidence": "Lista de targets vacía tras correlación de superficie.",
                        "recommendation": "Ejecutar sobre dominios/IP explícitos o ampliar discovery de activos externos.",
                    }]))

                for target in targets_to_scan:
                    free_status.markdown(f"[BlackHarrier SCANNER] Escaneando {target}...")
                    
                    assessment = free_assessment.run_full_assessment(
                        target=target,
                        include_dns=(free_scanner_depth == "Completo"),
                        port_type=port_type,
                        progress_callback=lambda msg, pct: free_scanner_progress(f"{target}: {msg}", pct)
                    )
                    
                    # Convert to normalized results
                    free_rows = assessment.get("normalized_results", [])
                    all_results.extend(normalize_results("BlackHarrier Scanner", free_rows))

                    nessus_structured["vulnerabilities"].extend(free_rows)

                    # Collect flat CVE list for exploit suggester
                    for cve_entry in assessment.get("phases", {}).get("cve_lookup") or []:
                        svc = str(cve_entry.get("service") or "")
                        ver = str(cve_entry.get("version") or "")
                        for cve in (cve_entry.get("vulnerabilities", {}).get("critical") or []) + \
                                   (cve_entry.get("vulnerabilities", {}).get("high") or []) + \
                                   (cve_entry.get("vulnerabilities", {}).get("medium") or []) + \
                                   (cve_entry.get("vulnerabilities", {}).get("low") or []):
                            if isinstance(cve, dict):
                                cve.setdefault("service", svc)
                                cve.setdefault("version", ver)
                                _all_cves_found.append(cve)
                
                free_status.markdown("✓ BlackHarrier Scanner completado")
            
            except Exception as e:
                st.warning(f"⚠️ Error en BlackHarrier Scanner: {str(e)[:200]}")
                all_results.extend(normalize_results("BlackHarrier Scanner", [{
                    "control": "BlackHarrier Scanner",
                    "status": "Error",
                    "severity": "Media",
                    "description": f"Error durante el escaneo: {str(e)[:100]}",
                    "evidence": "",
                    "recommendation": "Revisar configuración de red y timeouts",
                }]))


    # Future AI planner contract (internal only, no external AI call)
    ai_contract = build_ai_recon_contract(
        targets=external_targets,
        nmap_data=nmap_structured,
        nessus_data=nessus_structured,
    )
    all_results.extend(normalize_results("Correlación IA ofensiva", [contract_to_result(ai_contract)]))

    if _all_cves_found:
        cve_best = {}
        for cve in _all_cves_found:
            cve_id = str(cve.get("id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            score = float(cve.get("score", 0) or 0)
            current = cve_best.get(cve_id)
            if current is None or score > float(current.get("score", 0) or 0):
                cve_best[cve_id] = dict(cve)
        _all_cves_found = list(cve_best.values())

    all_results.extend(run_module("Validando TLS/HTTPS...", "TLS/HTTPS", scan_tls, target_url))
    all_results.extend(run_module("Analizando cabeceras...", "Cabeceras de seguridad", scan_security_headers, target_url, auth_client))
    all_results.extend(run_module("Analizando cookies...", "Cookies", scan_cookies, target_url))
    all_results.extend(run_module("Analizando CORS...", "CORS", scan_cors, target_url, pages))
    all_results.extend(run_module("Analizando métodos HTTP...", "Métodos HTTP", scan_http_methods, target_url))
    all_results.extend(run_module("Buscando recursos sensibles...", "Recursos sensibles", scan_sensitive_files, target_url))
    all_results.extend(run_module("Buscando directory listing...", "Directory Listing", scan_directory_listing, target_url))
    all_results.extend(run_module("Descubriendo APIs...", "API Discovery", scan_api_discovery, target_url, pages, auth_client))
    all_results.extend(run_module("Analizando formularios...", "Formularios", scan_forms_from_pages, pages))
    all_results.extend(run_module("Analizando CSRF...", "CSRF", scan_csrf_from_pages, pages))
    all_results.extend(run_module("Fingerprinting avanzado de tecnologías...", "Fingerprinting avanzado", scan_technology_fingerprint, target_url, pages))
    all_results.extend(normalize_results("Inteligencia ofensiva", build_attack_path_intel(
        all_results=all_results,
        discovered_urls=discovered_urls,
        cves=_all_cves_found,
    )))

    asset_intel_rows, candidate_targets = build_asset_intel_rows(
        target_url=target_url,
        external_targets=external_targets,
        nmap_data=nmap_structured,
        discovered_urls=discovered_urls,
        cves=_all_cves_found,
    )
    all_results.extend(normalize_results("Inteligencia de activos", asset_intel_rows))

    auth_attack_pages = dedupe_pages_by_url(build_auth_attack_pages(pages))
    attackable_pages = dedupe_pages_by_url([p for p in pages if is_generic_attack_page(p)])

    # Safety net: if generic filter yields zero but auth/registration pages exist, use them as attackable scope.
    if not attackable_pages:
        auth_fallback = [
            p for p in pages
            if str(p.get("classification", "")).lower() in ["auth", "registration"]
            and not is_blocked_or_error_page(p)
        ]
        attackable_pages = dedupe_pages_by_url(auth_fallback)

    return {
        "all_results": all_results,
        "pages": pages,
        "discovery": discovery,
        "discovered_urls": discovered_urls,
        "crawler_pages": crawler_pages,
        "auth_client_cfg": {"verify_ssl": verify_ssl},
        "auth_status": auth_status,
        "auth_used_login_url": auth_used_login_url,
        "auth_final_url": auth_final_url,
        "auth_cookies": auth_cookies,
        "use_auth": bool(use_auth),
        "attackable_pages": attackable_pages,
        "auth_attack_pages": auth_attack_pages,
        "scan_profile": scan_profile,
        "scan_payload_limit": scan_payload_limit,
        "is_aggressive_mode": is_aggressive_mode,
        "effective_auth_payload_limit": effective_auth_payload_limit,
        "effective_proxy_url": effective_proxy_url,
        "scan_mode": scan_mode,
        "port_scan_profile": port_scan_profile,
        "vuln_corr_profile": vuln_corr_profile,
        "all_cves_found": _all_cves_found,
        "enable_nmap": bool(enable_nmap),
        "nmap_profile": str(nmap_profile or "SAFE"),
        "include_udp": bool(include_udp),
        "nmap_timeout_seconds": int(nmap_timeout_seconds or 420),
        "nmap_scripts": str(nmap_scripts or "").strip(),
        "enable_nessus": bool(enable_nessus),
        "nessus_mode": str(nessus_mode or "nessus-local"),
        "nessus_base_url": str(nessus_base_url or "https://localhost:8834").strip(),
        "nessus_verify_ssl": bool(nessus_verify_ssl),
        "nessus_poll_seconds": int(nessus_poll_seconds or 180),
        "nessus_template_uuid": str(nessus_template_uuid or "basic").strip(),
        "nessus_access_key": str(nessus_access_key or "").strip(),
        "nessus_secret_key": str(nessus_secret_key or "").strip(),
        "audit_name": audit_name,
        "target_url": target_url,
        "sqli_intensity": st.session_state.get("_sqli_intensity", "Normal - 30 payloads"),
        "strict_fp_mode": bool(strict_fp_mode),
        "candidate_targets": candidate_targets,
    }


def _render_phase1_summary(state):
    pages = state["pages"]
    auth_attack_pages = state["auth_attack_pages"]
    attackable_pages = state["attackable_pages"]
    auth_status = str(state.get("auth_status", "No configurado") or "No configurado")
    auth_used_login_url = str(state.get("auth_used_login_url", "") or "")
    auth_cookie_names = sorted((state.get("auth_cookies") or {}).keys())
    use_auth = bool(state.get("use_auth", False))

    login_pages = list(auth_attack_pages)

    api_pages = [p for p in pages if p.get("classification") in ["api_candidate"]]
    admin_pages = [p for p in pages if p.get("classification") in ["admin_candidate"]]
    protected_pages = [p for p in pages if p.get("classification") in ["protected", "protected_redirect_to_auth"]]
    post_login_pages = [
        p for p in pages
        if str(p.get("discovery_context", "")).lower() == "post_login"
        and _is_meaningful_post_login_page(p)
    ]
    post_login_new = [p for p in post_login_pages if p.get("is_new_post_login")]
    display_post_login = post_login_new or post_login_pages
    post_login_protected = [
        p for p in display_post_login
        if str(p.get("classification", "")).lower() in {
            "protected",
            "protected_redirect_to_auth",
            "admin_candidate",
            "api_candidate",
            "sensitive_candidate",
        }
    ]

    st.markdown("---")
    st.markdown("### Fase 1 completada — Superficie descubierta")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Páginas totales", len(pages))
    c2.metric("Páginas atacables", len(attackable_pages))
    c3.metric("Logins / auth", len(login_pages))
    c4.metric("APIs candidatas", len(api_pages))
    c5.metric("Admin / protegidas", len(admin_pages) + len(protected_pages))

    if use_auth:
        if auth_status == "Autenticado":
            st.success(
                "Autenticación probada: AUTENTICADO"
                + (f" | Login usado: {auth_used_login_url}" if auth_used_login_url else "")
                + (f" | Cookies: {', '.join(auth_cookie_names[:6])}" if auth_cookie_names else "")
            )
        elif auth_status == "Indeterminado":
            st.warning(
                "Autenticación probada: INDETERMINADO"
                + (f" | Último login probado: {auth_used_login_url}" if auth_used_login_url else "")
            )
        elif auth_status == "Fallido":
            st.error(
                "Autenticación probada: FALLIDO"
                + (f" | Último login probado: {auth_used_login_url}" if auth_used_login_url else "")
            )
        else:
            st.info("Autenticación no ejecutada o sin credenciales completas en esta fase.")

    if login_pages:
        st.markdown("**Logins y rutas de autenticación detectadas:**")
        for p in login_pages[:15]:
            url = p.get("final_url") or p.get("url") or ""
            classification = p.get("classification", "")
            forms_count = len(p.get("forms") or [])
            st.markdown(f"- `{url}` — clasificación: **{classification}** — formularios: **{forms_count}**")
    else:
        st.info("No se detectaron rutas de autenticación. Los ataques de login no se ejecutarán.")

    if api_pages:
        st.markdown("**APIs candidatas:**")
        for p in api_pages[:10]:
            st.markdown(f"- `{p.get('final_url') or p.get('url', '')}`")

    if admin_pages:
        st.markdown("**Rutas administrativas:**")
        for p in admin_pages[:10]:
            st.markdown(f"- `{p.get('final_url') or p.get('url', '')}`")

    if use_auth:
        st.markdown(
            f"**Cobertura post-login:** {len(display_post_login)} URL(s) relevantes en sesión autenticada | "
            f"Rutas protegidas/candidatas: {len(post_login_protected)}"
        )
        if display_post_login:
            with st.expander("Ver URLs descubiertas post-login", expanded=False):
                for p in display_post_login[:30]:
                    u = p.get("final_url") or p.get("url") or ""
                    clf = p.get("classification") or "—"
                    st.markdown(
                        f"- `{u}` &nbsp; <span style='color:#9ad1ff;font-size:0.85em'>{html.escape(str(clf))}</span>",
                        unsafe_allow_html=True,
                    )
                if len(display_post_login) > 30:
                    st.caption(f"… y {len(display_post_login) - 30} más")


def _render_auth_post_login_summary(*, use_auth, auth_status, auth_used_login_url, auth_final_url, auth_cookies, pages, all_results):
    if not use_auth:
        return

    st.markdown("### Estado de autenticación y cobertura post-login")

    cookie_names = sorted((auth_cookies or {}).keys())
    status_upper = str(auth_status or "No configurado").upper()
    login_fragment = f" | Login usado: {auth_used_login_url}" if auth_used_login_url else ""
    final_fragment = f" | URL final auth: {auth_final_url}" if auth_final_url else ""
    cookies_fragment = f" | Cookies: {', '.join(cookie_names[:6])}" if cookie_names else ""

    if auth_status == "Autenticado":
        st.success(f"Autenticación: {status_upper}{login_fragment}{final_fragment}{cookies_fragment}")
    elif auth_status == "Indeterminado":
        st.warning(f"Autenticación: {status_upper}{login_fragment}{final_fragment}{cookies_fragment}")
    elif auth_status in ["Fallido", "Error"]:
        st.error(f"Autenticación: {status_upper}{login_fragment}{final_fragment}")
    else:
        st.info(f"Autenticación: {status_upper}{login_fragment}{final_fragment}")

    post_login_pages = [
        p for p in (pages or [])
        if str(p.get("discovery_context", "")).lower() == "post_login"
        and _is_meaningful_post_login_page(p)
    ]
    post_login_new = [p for p in post_login_pages if p.get("is_new_post_login")]
    display_post_login = post_login_new or post_login_pages
    protected_post_login = [
        p for p in display_post_login
        if str(p.get("classification", "")).lower() in {
            "protected",
            "protected_redirect_to_auth",
            "admin_candidate",
            "api_candidate",
            "sensitive_candidate",
        }
    ]

    st.caption(
        f"URLs post-login descubiertas: {len(display_post_login)} | "
        f"Rutas protegidas/candidatas: {len(protected_post_login)}"
    )

    if display_post_login:
        with st.expander("URLs descubiertas en sesión autenticada", expanded=False):
            for page in display_post_login[:40]:
                final_url = page.get("final_url") or page.get("url") or ""
                classification = page.get("classification") or "—"
                status_code = page.get("status_code") or ""
                st.markdown(
                    f"- `{final_url}` &nbsp; <span style='color:#a0c4ff;font-size:0.85em'>"
                    f"HTTP {html.escape(str(status_code))} · {html.escape(str(classification))}</span>",
                    unsafe_allow_html=True,
                )
            if len(display_post_login) > 40:
                st.caption(f"… y {len(display_post_login) - 40} más")

    coverage_row = next(
        (
            row for row in (all_results or [])
            if str(row.get("Módulo", "")).strip() == "Autenticación"
            and str(row.get("Control", "")).strip() == "Cobertura post-login"
        ),
        None,
    )
    if coverage_row:
        evidence_text = str(coverage_row.get("Evidencia", "") or "")
        if len(evidence_text) > 280:
            evidence_text = evidence_text[:280].rstrip() + "..."
        st.caption(f"Evidencia post-login: {evidence_text}")


if run_scan:
    target_url = _normalize_target_url(target_url)
    if not target_url:
        st.error("Debes introducir una URL objetivo.")
        st.stop()

    st.session_state["_target_url"] = target_url
    st.session_state["_sqli_intensity"] = sqli_intensity
    st.session_state["_enable_exploit_ai"] = enable_exploit_ai
    st.session_state["_exploit_ai_model"] = exploit_ai_model
    st.session_state["_authorized_engagement"] = True
    st.session_state["_offensive_scope_ack"] = True
    st.session_state["_parity_nmap_nessus"] = bool(parity_nmap_nessus)

    use_free_scanner = True

    state = _scan_phase1(
        target_url=target_url,
        scan_mode=scan_mode,
        verify_ssl=verify_ssl,
        use_burp_proxy=use_burp_proxy,
        burp_proxy_url=burp_proxy_url,
        use_auth=use_auth,
        login_url=login_url,
        username=username,
        password=password,
        max_auth_sqli_payloads=max_auth_sqli_payloads,
        audit_name=audit_name,
        strict_fp_mode=strict_fp_mode,
        enable_nmap=enable_nmap,
        nmap_profile=nmap_profile,
        include_udp=include_udp,
        nmap_timeout_seconds=nmap_timeout_seconds,
        nmap_scripts=nmap_scripts,
        enable_nessus=enable_nessus,
        nessus_mode=nessus_mode,
        nessus_base_url=nessus_base_url,
        nessus_access_key=nessus_access_key,
        nessus_secret_key=nessus_secret_key,
        nessus_verify_ssl=nessus_verify_ssl,
        nessus_poll_seconds=nessus_poll_seconds,
        nessus_template_uuid=nessus_template_uuid,
        nmap_bin=_nmap_bin,
    )

    st.session_state["phase1_state"] = state
    st.session_state["phase2_done"] = False

    _render_phase1_summary(state)

    # ── Partial results (passive only) ─────────────────────────────
    partial_df = pd.DataFrame(state["all_results"])
    st.session_state["last_audit_df"] = partial_df

    st.markdown("---")
    st.success(f"Reconocimiento completado. Páginas: {len(state['pages'])} | Atacables: {len(state['attackable_pages'])} | Auth targets: {len(state['auth_attack_pages'])}")
    # Rerender to enter the elif branch where the attack button is rendered
    st.rerun()

elif st.session_state.get("phase1_state") and not st.session_state.get("phase2_done"):
    state = st.session_state["phase1_state"]
    target_url = state["target_url"]
    audit_name = state["audit_name"]
    scan_mode = state["scan_mode"]
    pages = state["pages"]
    discovery = state["discovery"]
    all_results = list(state["all_results"])

    _render_phase1_summary(state)

    # ── Targets detail before confirming attack ──────────────────────────
    attackable_pages_preview = state.get("attackable_pages") or []
    auth_attack_pages_preview = state.get("auth_attack_pages") or []

    st.markdown("---")
    st.markdown("### Objetivos identificados para ataque ofensivo")

    col_att, col_auth = st.columns(2)

    with col_att:
        st.markdown(f"**Páginas atacables — XSS / SQLi / SSTI / SSRF / Redirect** ({len(attackable_pages_preview)})")
        if attackable_pages_preview:
            with st.expander("Ver listado completo", expanded=len(attackable_pages_preview) <= 10):
                for p in attackable_pages_preview[:50]:
                    u = p.get("final_url") or p.get("url") or ""
                    clf = p.get("classification") or "—"
                    st.markdown(f"- `{u}` &nbsp; <span style='color:#a0c4ff;font-size:0.85em'>{html.escape(clf)}</span>", unsafe_allow_html=True)
                if len(attackable_pages_preview) > 50:
                    st.caption(f"… y {len(attackable_pages_preview) - 50} más")
        else:
            st.info("Sin páginas atacables genéricas.")

    with col_auth:
        st.markdown(f"**Targets de autenticación — Auth SQLi / Brute-force** ({len(auth_attack_pages_preview)})")
        if auth_attack_pages_preview:
            with st.expander("Ver listado completo", expanded=len(auth_attack_pages_preview) <= 10):
                for p in auth_attack_pages_preview[:30]:
                    u = p.get("final_url") or p.get("url") or ""
                    forms_n = len(p.get("forms") or [])
                    st.markdown(f"- `{u}` &nbsp; <span style='color:#ffadad;font-size:0.85em'>forms: {forms_n}</span>", unsafe_allow_html=True)
                if len(auth_attack_pages_preview) > 30:
                    st.caption(f"… y {len(auth_attack_pages_preview) - 30} más")
        else:
            st.info("Sin targets de autenticación detectados.")

    st.markdown("---")
    run_offensive = st.button("Lanzar ataques ofensivos", type="primary")

    if not run_offensive:
        st.stop()

    # ── Phase 2: pull context from session state ─────────────────────────
    is_aggressive_mode    = state["is_aggressive_mode"]
    scan_payload_limit    = state["scan_payload_limit"]
    effective_auth_payload_limit = state["effective_auth_payload_limit"]
    sqli_intensity        = state["sqli_intensity"]
    strict_fp_mode        = bool(state.get("strict_fp_mode", True))
    attackable_pages      = state["attackable_pages"]
    auth_attack_pages     = state["auth_attack_pages"]
    effective_proxy_url   = state["effective_proxy_url"]
    auth_status           = str(state.get("auth_status", "")).strip()

    offensive_delay = min(float(state["scan_profile"].get("delay", 0.35)), 0.05)

    _configure_http_defaults_compat(
        delay=offensive_delay,
        verify_ssl=state["auth_client_cfg"]["verify_ssl"],
        proxy_url=effective_proxy_url,
    )
    auth_client = HttpClient()
    auth_client.verify_ssl = state["auth_client_cfg"]["verify_ssl"]
    auth_cookies = state.get("auth_cookies") or {}
    if auth_cookies:
        auth_client.session.cookies.update(auth_cookies)

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

    allow_offensive_actions = True

    # ── Parallel offensive HTTP modules (all independent, no Playwright) ────
    if allow_offensive_actions:
        effective_pages = attackable_pages or [{
            "url": target_url, "final_url": target_url,
            "status_code": 200, "html": "", "forms": [],
            "classification": "fallback_target",
        }]

        parallel_jobs, ranked_plan, target_features = build_adaptive_parallel_jobs(
            target_url=target_url,
            pages=pages,
            effective_pages=effective_pages,
            auth_client=auth_client,
            scan_payload_limit=scan_payload_limit,
        )
        parallel_jobs, ranked_plan = reprioritize_for_authenticated_session(
            parallel_jobs,
            ranked_plan,
            auth_status,
        )

        with st.expander("Plan ofensivo inteligente (AI Planner)", expanded=False):
            st.caption(
                "El orden se calcula por puntuación contextual: recomendaciones AI por página, "
                "efectividad histórica por módulo y señales detectadas en la superficie actual."
            )
            st.json({
                "strict_fp_mode": bool(strict_fp_mode),
                "target_features": target_features,
                "ranked_modules": [
                    {
                        "module": item["name"],
                        "score": item["score"],
                        "ai_score": item["ai_score"],
                        "memory_score": item["memory_score"],
                        "context_boost": item["context_boost"],
                    }
                    for item in ranked_plan
                ],
            })

        parallel_status = st.empty()
        parallel_status.info(f"Ejecutando {len(parallel_jobs)} módulos ofensivos en paralelo (modo adaptativo)...")

        parallel_results: dict[str, list] = {}
        queue = list(parallel_jobs)
        in_flight: dict = {}
        pressure = 0
        max_pressure = 0
        window = adaptive_parallel_window(pressure, strict_mode=bool(strict_fp_mode))
        done_count = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            while queue and len(in_flight) < window:
                name, func, args = queue.pop(0)
                in_flight[executor.submit(_run_raw, func, *args)] = name

            while in_flight:
                done_set, _ = concurrent.futures.wait(
                    set(in_flight.keys()),
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )

                for future in done_set:
                    name = in_flight.pop(future)
                    done_count += 1

                    try:
                        raw = future.result()
                        normalized = normalize_results(name, sanitize_module_results(raw or []))
                        if not normalized:
                            normalized = normalize_results(name, [{
                                "control": name,
                                "status": "No evidenciado",
                                "severity": "Informativa",
                                "description": "Módulo ejecutado sin observaciones en esta ejecución.",
                                "evidence": "Sin hallazgos ni errores técnicos reportados por el módulo.",
                                "recommendation": "Mantener monitorización y repetir en siguientes iteraciones.",
                            }])
                        parallel_results[name] = normalized
                    except Exception:
                        normalized = normalize_results(name, [{
                            "control": name,
                            "status": "Error",
                            "severity": "Media",
                            "description": "Error inesperado en módulo paralelo.",
                            "evidence": traceback.format_exc(),
                            "recommendation": "Revisar trazas y dependencias del módulo.",
                        }])
                        parallel_results[name] = normalized

                    module_pressure = estimate_defense_pressure(parallel_results.get(name, []))
                    pressure = max(0, pressure - 1) + module_pressure
                    max_pressure = max(max_pressure, pressure)
                    window = adaptive_parallel_window(pressure, strict_mode=bool(strict_fp_mode))

                    while queue and len(in_flight) < window:
                        next_name, next_func, next_args = queue.pop(0)
                        in_flight[executor.submit(_run_raw, next_func, *next_args)] = next_name

                    parallel_status.info(
                        f"Módulos completados: {done_count}/{len(parallel_jobs)} | "
                        f"Último: {name} | presión defensiva: {pressure} | ventana: {window}"
                    )

        parallel_status.success(
            f"Módulos ofensivos HTTP completados ({len(parallel_jobs)}). "
            f"Pico de presión defensiva observado: {max_pressure}."
        )

        all_results.extend(normalize_results("Orquestación ofensiva", [{
            "control": "Planificador adaptativo anti-bloqueo",
            "status": "Comprobado",
            "severity": "Informativa",
            "description": "La ejecución paralela ajustó dinámicamente la concurrencia ante señales de WAF/rate-limit.",
            "evidence": (
                f"Módulos planificados: {len(parallel_jobs)} | "
                f"Pico presión defensiva: {max_pressure} | "
                f"Modo estricto anti-FP: {bool(strict_fp_mode)}"
            ),
            "recommendation": "Mantener modo adaptativo para reducir falsos negativos por bloqueo temporal o rate limiting.",
        }]))

        for name, _ , _ in parallel_jobs:
            all_results.extend(parallel_results.get(name, []))
    else:
        all_results.extend(normalize_results("Orquestación ofensiva", [{
            "control": "Planificador adaptativo anti-bloqueo",
            "status": "No probado",
            "severity": "Informativa",
            "description": "La fase ofensiva paralela quedó desactivada por falta de consentimiento reforzado.",
            "evidence": "offensive_scope_ack=False",
            "recommendation": "Confirmar autorización ofensiva si se quiere ejecutar la batería de explotación controlada.",
        }]))

    # ── Auth SQLi (Playwright browser — sequential, must stay single-threaded) ──
    if auth_status == "Autenticado":
        auth_sqli_results = [{
            "control": "SQLi/bypass en autenticación",
            "status": "No probado",
            "severity": "Informativa",
            "description": "Se omitió bypass SQLi de login porque las credenciales válidas ya otorgaron acceso.",
            "evidence": "Autenticación previa confirmada en Fase 1.",
            "recommendation": "Enfocar pruebas en autorización post-login, exposición de datos y privilegios.",
        }]
    elif allow_offensive_actions:
        with st.spinner(f"Probando SQLi en autenticación ({sqli_intensity})..."):
            auth_sqli_results = scan_auth_sqli(
                pages=auth_attack_pages,
                client=auth_client,
                max_payloads=effective_auth_payload_limit,
                headless=True,
                progress_callback=attack_progress_event,
            )
    else:
        auth_sqli_results = [{
            "control": "SQLi/bypass en autenticación",
            "status": "No probado",
            "severity": "Informativa",
            "description": "Se omitió SQLi de autenticación por falta de consentimiento reforzado.",
            "evidence": "offensive_scope_ack=False",
            "recommendation": "Confirmar autorización ofensiva para evaluar bypasses de login.",
        }]

    should_escalate_auth = (
        auth_status != "Autenticado"
        and
        sqli_intensity == "Normal - 30 payloads"
        and auth_attack_pages
        and auth_sqli_results
        and all(str(item.get("status", "")) == "No evidenciado" for item in auth_sqli_results)
    )

    if should_escalate_auth:
        with st.spinner("Sin bypass inicial en login. Ejecutando segunda pasada exhaustiva..."):
            auth_sqli_results = scan_auth_sqli(
                pages=auth_attack_pages,
                client=auth_client,
                max_payloads=None,
                headless=True,
                progress_callback=attack_progress_event,
            )
        auth_sqli_results.append({
            "control": "Cobertura SQLi Auth",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "Se ejecutó escalado automático a batería exhaustiva tras una primera pasada sin bypass.",
            "evidence": f"Primera pasada: {sqli_intensity} | Segunda pasada: Exhaustiva | Objetivos auth: {len(auth_attack_pages)}",
            "recommendation": "Mantener validación manual en flujos MFA/OAuth y lógica de negocio no cubierta por payloads genéricos.",
        })

    all_results.extend(normalize_results("SQL Injection Auth (Browser)", auth_sqli_results))

    attack_finished("Ejecución ofensiva finalizada.")

    # ── Agente IA – Propuesta de Exploits ───────────────────────────────────
    _cves_for_exploits = list(state.get("all_cves_found") or [])
    _exploit_ai_enabled = bool(st.session_state.get("_enable_exploit_ai", True))
    _exploit_ai_model = str(st.session_state.get("_exploit_ai_model", "llama3") or "llama3")

    if _cves_for_exploits and _exploit_ai_enabled:
        try:
            from scanner.exploit_suggester import build_exploit_suggestions, format_suggestions_for_display
            with st.spinner("Agente IA analizando CVEs y generando propuestas de exploits..."):
                exploit_suggestions = build_exploit_suggestions(
                    cves=_cves_for_exploits,
                    target_url=target_url,
                    ollama_model=_exploit_ai_model,
                    use_ollama=True,
                    max_ai_queries=5,
                )
            st.session_state["last_exploit_suggestions"] = exploit_suggestions

            if exploit_suggestions:
                st.markdown("---")
                st.subheader(f"🤖 Agente IA – Propuesta de Exploits ({len(exploit_suggestions)} CVEs analizados)")

                # Summary metrics
                _crit = sum(1 for s in exploit_suggestions if s.get("severity") == "critical")
                _high = sum(1 for s in exploit_suggestions if s.get("severity") == "high")
                _ai_used = sum(1 for s in exploit_suggestions if s.get("ai_used"))
                _ec1, _ec2, _ec3, _ec4 = st.columns(4)
                _ec1.metric("CVEs analizados", len(exploit_suggestions))
                _ec2.metric("Críticos / Altos", f"{_crit} / {_high}")
                _ec3.metric("Enriquecidos con IA", _ai_used)
                _ec4.metric("Modo IA", _exploit_ai_model if _ai_used else "Offline")

                for sug in exploit_suggestions:
                    _sev = sug.get("severity", "info")
                    _sev_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(_sev, "⚪")
                    _ai_badge = " · **[IA]**" if sug.get("ai_used") else ""
                    _title = f"{_sev_color} **{sug['cve_id']}** (CVSS {sug['score']:.1f}) – {sug['family']}{_ai_badge}"
                    with st.expander(_title, expanded=(_sev in ("critical", "high"))):
                        col_l, col_r = st.columns(2)
                        with col_l:
                            st.markdown(f"**Servicio**: `{sug.get('service','')} {sug.get('version','')}`.strip()")
                            st.markdown(f"**Técnica**: {sug.get('technique','')}")
                            st.markdown(f"**Vector**: {sug.get('vector','')}")
                            if sug.get("msf_hint"):
                                st.code(sug["msf_hint"], language="bash")
                        with col_r:
                            st.markdown(f"**Remediación**: {sug.get('remediation','')}")
                            if sug.get("description"):
                                st.caption(sug["description"][:250])

                        if sug.get("ai_analysis"):
                            _ai = sug["ai_analysis"]
                            if _ai.get("resumen"):
                                st.info(f"**Análisis IA**: {_ai['resumen']}")
                            if _ai.get("pasos_explotacion"):
                                st.markdown("**Pasos de explotación (IA):**")
                                for i, paso in enumerate(_ai["pasos_explotacion"], 1):
                                    st.markdown(f"{i}. {paso}")
                            if _ai.get("herramientas_recomendadas"):
                                st.markdown(f"**Herramientas**: {', '.join(_ai['herramientas_recomendadas'])}")
                            if _ai.get("nivel_dificultad"):
                                st.markdown(f"**Dificultad de explotación**: {_ai['nivel_dificultad']}")

                        if sug.get("poc"):
                            _lang = "html" if sug["poc"].strip().startswith("<") else "python"
                            st.markdown("**PoC / Plantilla de ataque:**")
                            st.code(sug["poc"], language=_lang)
        except Exception as _exp_err:
            st.warning(f"⚠️ Error en agente de exploits: {str(_exp_err)[:200]}")
    elif _exploit_ai_enabled and not _cves_for_exploits:
        st.info("ℹ️ El agente IA de exploits no encontró CVEs en esta auditoría. Activa BlackHarrier Scanner para buscar vulnerabilidades en servicios de red.")

    all_results.extend(build_offensive_assurance_result(all_results, aggressive_mode=is_aggressive_mode))
    all_results = deduplicate_results(all_results)
    all_results = apply_false_positive_guard(all_results, pages, strict_mode=strict_fp_mode)

    df = pd.DataFrame(all_results)

    st.session_state["last_audit_df"] = df
    st.session_state["last_audit_results"] = all_results
    st.session_state["last_audit_pages"] = pages
    st.session_state["last_audit_discovery"] = discovery
    st.session_state["last_report_bytes"] = None

    # ── Adaptive Learning Integration ─────────────────────────────────
    try:
        orchestrator = AdaptiveOrchestrator()

        # Extract frameworks and WAF types from discovery results
        detected_frameworks = []
        detected_waf = []
        for result in all_results:
            if result.get("Módulo") == "Reconocimiento":
                framework_info = result.get("evidence", "")
                if "react" in framework_info.lower():
                    detected_frameworks.append("react")
                if "next.js" in framework_info.lower():
                    detected_frameworks.append("next.js")
                if "angular" in framework_info.lower():
                    detected_frameworks.append("angular")
                if "vue" in framework_info.lower():
                    detected_frameworks.append("vue")
                if "django" in framework_info.lower():
                    detected_frameworks.append("django")
                if "flask" in framework_info.lower():
                    detected_frameworks.append("flask")
                if "cloudflare" in framework_info.lower():
                    detected_waf.append("cloudflare")
                if "akamai" in framework_info.lower():
                    detected_waf.append("akamai")
                if "modsecurity" in framework_info.lower():
                    detected_waf.append("modsecurity")

        # Record learnings from this audit
        orchestrator.continuous_learning_from_audit(
            audit_results={
                "detected_frameworks": list(set(detected_frameworks)),
                "detected_waf": list(set(detected_waf)),
                "findings": [
                    {
                        "attack_type": result.get("Módulo", "unknown"),
                        "payload": result.get("evidence", "")[:100],
                        "severity": result.get("Severidad", "Media"),
                        "description": result.get("Descripción", ""),
                    }
                    for result in all_results
                    if result.get("Resultado") in ["Hallazgo", "Posible hallazgo"]
                ],
            },
            target_url=target_url,
        )

        # Display adaptation metrics
        adaptation_summary = orchestrator.get_adaptation_summary()
        with st.expander("📊 Métricas de Aprendizaje Adaptativo", expanded=False):
            col_fw, col_att, col_bypass, col_env = st.columns(4)
            col_fw.metric(
                "🔍 Frameworks Aprendidos",
                adaptation_summary["total_frameworks_seen"],
            )
            col_att.metric(
                "⚔️ Ataques Registrados",
                adaptation_summary["total_attacks_recorded"],
            )
            col_bypass.metric(
                "🛡️ Técnicas de Bypass",
                adaptation_summary["bypass_techniques_learned"],
            )
            col_env.metric(
                "🎯 Entornos Perfilados",
                adaptation_summary["target_environments_profiled"],
            )
            st.caption(
                f"Último aprendizaje: {adaptation_summary['last_updated']}"
            )

    except Exception as e:
        st.warning(f"No se pudo actualizar el aprendizaje adaptativo: {e}")

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

    _render_auth_post_login_summary(
        use_auth=state.get("use_auth", False),
        auth_status=state.get("auth_status", "No configurado"),
        auth_used_login_url=state.get("auth_used_login_url", ""),
        auth_final_url=state.get("auth_final_url", ""),
        auth_cookies=state.get("auth_cookies") or {},
        pages=pages,
        all_results=all_results,
    )

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

    try:
        save_audit(audit_name, target_url, all_results)
    except Exception:
        all_results.extend(normalize_results("Persistencia", [pipeline_error_result(
            control="Persistencia",
            description="No se pudo guardar la auditoría en base de datos.",
            evidence=traceback.format_exc(),
            recommendation="Comprobar permisos de escritura y estado del backend de almacenamiento.",
        )]))

    try:
        learning_summary = record_audit_feedback(target_url, pages, all_results)
        st.caption(
            "AI Agent aprendizaje actualizado: "
            f"{learning_summary.get('results', 0)} resultados, "
            f"{learning_summary.get('findings', 0)} hallazgos, "
            f"{learning_summary.get('errors', 0)} errores."
        )
    except Exception:
        all_results.extend(normalize_results("AI Agent", [pipeline_error_result(
            control="AI Agent Learning",
            description="No se pudo actualizar el aprendizaje del agente AI.",
            evidence=traceback.format_exc(),
            recommendation="Revisar storage/ai_agent_memory.json y permisos de escritura.",
        )]))
        df = pd.DataFrame(all_results)
        st.session_state["last_audit_df"] = df

    st.session_state["phase2_done"] = True
    st.session_state["phase1_state"] = None

    report_path = None
    try:
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
        st.session_state["last_report_bytes"] = _get_report_bytes_if_available(report_path)
    except Exception:
        report_trace = traceback.format_exc()
        st.error("No se pudo generar el informe Word. Revisa logs y dependencias de reportes.")
        st.caption(f"Detalle técnico: {report_trace.splitlines()[-1] if report_trace else 'Error no identificado'}")
        st.session_state["last_report_error"] = report_trace
        try:
            os.makedirs("logs", exist_ok=True)
            with open("logs/report_generation.log", "a", encoding="utf-8") as log_file:
                log_file.write(f"\n[{datetime.now().isoformat()}] Word report generation error\n")
                log_file.write(report_trace)
                if not report_trace.endswith("\n"):
                    log_file.write("\n")
        except Exception:
            pass
        st.session_state["last_report_path"] = None
        st.session_state["last_report_bytes"] = None

    if report_path:
        report_bytes = st.session_state.get("last_report_bytes")
        if report_bytes:
            st.download_button(
                label="Descargar informe Word",
                data=report_bytes,
                file_name=os.path.basename(report_path),
                mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                on_click="ignore",
                key=f"download_word_{os.path.basename(report_path)}_{len(report_bytes)}",
            )
        else:
            st.warning("El informe se generó, pero no está disponible para descarga en esta sesión.")
elif st.session_state.get("last_audit_df") is not None:
    df = st.session_state["last_audit_df"]
    report_path = st.session_state.get("last_report_path")
    report_bytes = st.session_state.get("last_report_bytes")

    if report_path and not report_bytes:
        report_bytes = _get_report_bytes_if_available(report_path)
        st.session_state["last_report_bytes"] = report_bytes
        if not report_bytes:
            st.session_state["last_report_path"] = None
            report_path = None

    st.subheader("Resultados de la última auditoría")
    st.dataframe(df, width="stretch")

    if report_path and report_bytes:
        st.download_button(
            label="Descargar informe Word",
            data=report_bytes,
            file_name=os.path.basename(report_path),
            mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            on_click="ignore",
            key=f"download_last_word_{os.path.basename(report_path)}_{len(report_bytes)}",
        )
