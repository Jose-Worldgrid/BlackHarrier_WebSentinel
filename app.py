import html
import os
import traceback
import concurrent.futures
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
from scanner.ssti import scan_ssti
from scanner.ssrf import scan_ssrf_hints
from scanner.path_traversal import scan_path_traversal
from scanner.dependency_exposure import scan_dependency_exposure
from scanner.discovery import discover_surface
from scanner.auth_sqli import scan_auth_sqli
from scanner.ai_agent import enrich_pages_with_ai_context, record_audit_feedback
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
    unique = []
    seen = set()
    for page in pages or []:
        key = str(page.get("final_url") or page.get("url") or "").strip().rstrip("/")
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(page)
    return unique


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


def _scan_phase1(target_url, scan_mode, verify_ssl, use_burp_proxy, burp_proxy_url, use_auth, login_url, username, password, max_auth_sqli_payloads, audit_name, strict_fp_mode):
    """Phase 1: crawl, discovery, passive recon. Returns session state dict."""
    all_results = []
    scan_profile = SCAN_MODES.get(scan_mode, {})
    scan_delay = float(scan_profile.get("delay", 0.35))
    scan_payload_limit = scan_profile.get("max_payloads")
    is_aggressive_mode = bool(scan_profile.get("aggressive", False))
    effective_auth_payload_limit = resolve_payload_limit(scan_payload_limit, max_auth_sqli_payloads)
    effective_proxy_url = burp_proxy_url.strip() if use_burp_proxy else None

    # Phase 1: Desabilitar SSL verification para módulos pasivos
    # Los módulos de reconnaissance (headers, cookies, CORS, etc.) no requieren SSL strict
    # porque no realizan pruebas ofensivas. Esto evita errores con certificados autofirmados.
    _configure_http_defaults_compat(delay=scan_delay, verify_ssl=False, proxy_url=effective_proxy_url)
    auth_client = HttpClient(verify_ssl=False)

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

    if use_auth:
        auth_client, auth_results = authenticate(login_url, username, password)
        auth_client.verify_ssl = verify_ssl
        all_results.extend(normalize_results("Autenticación", auth_results))

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
            discovery = discover_surface(
                target_url,
                client=auth_client,
                seed_pages=crawler_pages,
                max_active_checks=500 if is_aggressive_mode else 300,
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

    try:
        pages = enrich_pages_with_ai_context(pages)
    except Exception:
        all_results.extend(normalize_results("Enriquecimiento AI", [pipeline_error_result(
            control="Enriquecimiento AI",
            description="Error en enriquecimiento AI; se continúa sin este paso.",
            evidence=traceback.format_exc(),
            recommendation="Revisar dependencias del agente AI.",
        )]))

    discovered_urls = discovery.get("discovered") or []

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
    all_results.extend(run_module("Fingerprinting avanzado de tecnologías...", "Fingerprinting avanzado", scan_technology_fingerprint, target_url, pages))

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
        "attackable_pages": attackable_pages,
        "auth_attack_pages": auth_attack_pages,
        "scan_profile": scan_profile,
        "scan_payload_limit": scan_payload_limit,
        "is_aggressive_mode": is_aggressive_mode,
        "effective_auth_payload_limit": effective_auth_payload_limit,
        "effective_proxy_url": effective_proxy_url,
        "scan_mode": scan_mode,
        "audit_name": audit_name,
        "target_url": target_url,
        "sqli_intensity": st.session_state.get("_sqli_intensity", "Normal - 30 payloads"),
        "strict_fp_mode": bool(strict_fp_mode),
    }


def _render_phase1_summary(state):
    pages = state["pages"]
    auth_attack_pages = state["auth_attack_pages"]
    attackable_pages = state["attackable_pages"]

    login_pages = list(auth_attack_pages)

    api_pages = [p for p in pages if p.get("classification") in ["api_candidate"]]
    admin_pages = [p for p in pages if p.get("classification") in ["admin_candidate"]]
    protected_pages = [p for p in pages if p.get("classification") in ["protected", "protected_redirect_to_auth"]]

    st.markdown("---")
    st.markdown("### Fase 1 completada — Superficie descubierta")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Páginas totales", len(pages))
    c2.metric("Páginas atacables", len(attackable_pages))
    c3.metric("Logins / auth", len(login_pages))
    c4.metric("APIs candidatas", len(api_pages))
    c5.metric("Admin / protegidas", len(admin_pages) + len(protected_pages))

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


if run_scan:
    if not target_url:
        st.error("Debes introducir una URL objetivo.")
        st.stop()

    st.session_state["_target_url"] = target_url
    st.session_state["_sqli_intensity"] = sqli_intensity

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

    offensive_delay = min(float(state["scan_profile"].get("delay", 0.35)), 0.05)

    _configure_http_defaults_compat(
        delay=offensive_delay,
        verify_ssl=state["auth_client_cfg"]["verify_ssl"],
        proxy_url=effective_proxy_url,
    )
    auth_client = HttpClient()

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

    # ── Parallel offensive HTTP modules (all independent, no Playwright) ────
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
    parallel_status.info(f"Ejecutando {len(parallel_jobs)} módulos ofensivos en paralelo...")

    parallel_results: dict[str, list] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {
            executor.submit(_run_raw, func, *args): name
            for name, func, args in parallel_jobs
        }
        done_count = 0
        for future in concurrent.futures.as_completed(future_map):
            name = future_map[future]
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
                parallel_results[name] = normalize_results(name, [{
                    "control": name,
                    "status": "Error",
                    "severity": "Media",
                    "description": "Error inesperado en módulo paralelo.",
                    "evidence": traceback.format_exc(),
                    "recommendation": "Revisar trazas y dependencias del módulo.",
                }])
            parallel_status.info(f"Módulos completados: {done_count}/{len(parallel_jobs)} | Último: {name}")

    parallel_status.success(f"Módulos ofensivos HTTP completados ({len(parallel_jobs)}).")

    for name, _ , _ in parallel_jobs:
        all_results.extend(parallel_results.get(name, []))

    # ── Auth SQLi (Playwright browser — sequential, must stay single-threaded) ──
    with st.spinner(f"Probando SQLi en autenticación ({sqli_intensity})..."):
        auth_sqli_results = scan_auth_sqli(
            pages=auth_attack_pages,
            client=auth_client,
            max_payloads=effective_auth_payload_limit,
            headless=True,
            progress_callback=attack_progress_event,
        )

    should_escalate_auth = (
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

    all_results.extend(build_offensive_assurance_result(all_results, aggressive_mode=is_aggressive_mode))
    all_results = apply_false_positive_guard(all_results, pages, strict_mode=strict_fp_mode)

    df = pd.DataFrame(all_results)

    st.session_state["last_audit_df"] = df
    st.session_state["last_audit_results"] = all_results
    st.session_state["last_audit_pages"] = pages
    st.session_state["last_audit_discovery"] = discovery
    st.session_state["last_report_bytes"] = None

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
        st.error("No se pudo generar el informe Word. Revisa logs y dependencias de reportes.")
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
