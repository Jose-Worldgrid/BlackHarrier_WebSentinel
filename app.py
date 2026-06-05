import html
import os
import re
import traceback
import concurrent.futures
import ipaddress
from urllib.parse import urlparse, urljoin
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
from scanner.discovery import discover_surface, classify_url as classify_discovery_url, get_soft404_baseline
from scanner.katana_discovery import run_katana_discovery
from scanner.auth_sqli import scan_auth_sqli
from scanner import network_recon
from scanner.user_enum import scan_user_enumeration
from scanner.port_services import scan_port_services
from scanner.vuln_correlation import scan_vulnerability_correlation
from scanner.nmap_scanner import run_nmap_recon
from scanner.nessus_client import NessusConfig, run_nessus_assessment
from scanner.free_assessment import FreeAssessment
from scanner.cve_lookup import CVELookup
from scanner.cve_intel import enrich_cves_with_free_intel
from scanner.external_tools_pipeline import run_external_tools_pipeline, verificar_endpoints_httpx
from scanner.tool_detection import detect_external_web_tools
from scanner.kali_processing import (
    build_login_db_intel_rows,
    build_kali_procedure_rows,
    run_kali_quick_fingerprint,
)
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
        if is_blocked_or_error_page(page):
            continue
        if _looks_like_not_found_page(page):
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
        if is_blocked_or_error_page(page) or _looks_like_not_found_page(page):
            continue
        lower_url = url.lower()
        classification = str(page.get("classification") or "").lower()
        status = _safe_status_int(page.get("status_code"))
        if status in {0, 404}:
            continue
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


def _build_external_auth_params(auth_status, auth_cookies):
    cookie_map = dict(auth_cookies or {})
    if not cookie_map:
        return {}

    status = str(auth_status or "").strip().lower()
    if status not in {"autenticado", "indeterminado"}:
        return {}

    pairs = []
    for key in sorted(cookie_map.keys()):
        k = str(key or "").strip()
        v = str(cookie_map.get(key) or "").strip()
        if not k:
            continue
        pairs.append(f"{k}={v}")

    cookie_header = "; ".join(pairs).strip()
    if not cookie_header:
        return {}

    return {
        "cookie": cookie_header,
        "headers": [f"Cookie: {cookie_header}"],
    }


def _extract_cookie_details_from_jar(cookie_jar, max_items=24):
    details = []
    seen = set()

    for cookie in cookie_jar or []:
        name = str(getattr(cookie, "name", "") or "").strip()
        if not name or name in seen:
            continue

        seen.add(name)
        rest = getattr(cookie, "_rest", {}) or {}
        same_site = str(rest.get("SameSite") or rest.get("samesite") or "").strip()
        http_only = bool(
            rest.get("HttpOnly")
            or rest.get("httponly")
            or ("HttpOnly" in rest)
            or ("httponly" in rest)
        )

        details.append({
            "name": name,
            "value": str(getattr(cookie, "value", "") or ""),
            "domain": str(getattr(cookie, "domain", "") or ""),
            "path": str(getattr(cookie, "path", "") or "/"),
            "secure": bool(getattr(cookie, "secure", False)),
            "http_only": http_only,
            "same_site": same_site or "-",
            "expires": int(getattr(cookie, "expires", 0) or 0),
        })

        if len(details) >= max_items:
            break

    return details


def _merge_cookie_maps(*cookie_maps):
    merged = {}
    for cookie_map in cookie_maps or []:
        for key, value in (cookie_map or {}).items():
            name = str(key or "").strip()
            if not name:
                continue
            merged[name] = str(value or "")
    return merged


def _merge_cookie_details(*cookie_detail_sets, max_items=24):
    merged = []
    seen = set()
    for detail_set in cookie_detail_sets or []:
        for item in detail_set or []:
            name = str((item or {}).get("name") or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            merged.append(dict(item))
            if len(merged) >= max_items:
                return merged
    return merged


def _build_cookie_details_fallback(auth_cookies, max_items=24):
    details = []
    for name in sorted((auth_cookies or {}).keys()):
        key = str(name or "").strip()
        if not key:
            continue
        value = str((auth_cookies or {}).get(name) or "")
        details.append({
            "name": key,
            "value": value,
            "domain": "",
            "path": "/",
            "secure": False,
            "http_only": False,
            "same_site": "-",
            "expires": 0,
        })
        if len(details) >= max_items:
            break
    return details


def _render_cookie_capture_panel(auth_cookie_details, auth_cookies=None, *, max_items=24):
    details = list(auth_cookie_details or [])
    if not details and auth_cookies:
        details = _build_cookie_details_fallback(auth_cookies, max_items=max_items)

    if not details:
        return

    with st.expander("Cookies de sesión capturadas (validación controlada)", expanded=False):
        safe_rows = []
        replay_pairs = []
        for cookie in details[:max_items]:
            name = str(cookie.get("name") or "")
            value = str(cookie.get("value") or "")
            replay_pairs.append(f"{name}={value}")
            safe_rows.append({
                "name": name,
                "value_preview": (value[:12] + "...") if len(value) > 15 else value,
                "domain": cookie.get("domain") or "",
                "path": cookie.get("path") or "/",
                "secure": bool(cookie.get("secure")),
                "http_only": bool(cookie.get("http_only")),
                "same_site": cookie.get("same_site") or "-",
            })
        st.dataframe(pd.DataFrame(safe_rows), width="stretch")
        st.markdown("**Cookie header para replay de sesión (entorno autorizado):**")
        st.code("; ".join(replay_pairs), language="bash")


def _extract_post_login_route_hints(target_url, pages, max_hints=60):
    """Extract likely authenticated routes from HTML/runtime/forms without hardcoding app-specific paths."""
    base = urlparse(str(target_url or "").strip())
    if not base.scheme or not base.netloc:
        return []

    origin = f"{base.scheme}://{base.netloc}"
    same_host = base.hostname or ""

    route_token = re.compile(r"/(?:[A-Za-z0-9_\-]{2,}/){0,6}[A-Za-z0-9_\-]{2,}(?:\?[A-Za-z0-9_\-=&%]+)?")
    static_ext = (
        ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    )
    ignored_query_tokens = ("_rsc=", "utm_", "fbclid=", "gclid=")

    discovered = []
    seen = set()

    def _add_candidate(raw_url):
        text = str(raw_url or "").strip().strip('"\'')
        if not text:
            return
        if text.startswith("javascript:") or text.startswith("data:"):
            return

        if text.startswith("/"):
            full = urljoin(origin, text)
        elif text.startswith("http://") or text.startswith("https://"):
            full = text
        else:
            return

        parsed = urlparse(full)
        if not parsed.scheme or not parsed.netloc:
            return
        if parsed.hostname != same_host:
            return

        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.query:
            normalized = f"{normalized}?{parsed.query}"
        if normalized in seen:
            return
        if len(parsed.path or "") < 2:
            return

        low_path = (parsed.path or "").lower()
        low_query = (parsed.query or "").lower()
        if low_path.endswith(static_ext):
            return
        if any(tok in low_query for tok in ignored_query_tokens):
            return
        if any(tok in low_path for tok in ["/login", "/signin", "/auth", "/session"]) and any(
            tok in low_query for tok in ["redirect=", "next=", "returnurl=", "callbackurl="]
        ):
            return

        seen.add(normalized)
        discovered.append(normalized)

    for page in pages or []:
        html_sources = [
            str(page.get("html") or ""),
            str(page.get("rendered_html") or ""),
            str((page.get("browser_runtime") or {}).get("html") or ""),
        ]
        for html_blob in html_sources:
            if not html_blob:
                continue
            for path in route_token.findall(html_blob):
                _add_candidate(path)

        for form in (page.get("forms") or []):
            _add_candidate(form.get("action") or "")

    return discovered[:max_hints]


_DB_PORT_HINTS = {
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    27017: "MongoDB",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
}

_DB_SERVICE_HINTS = {
    "mysql": "MySQL/MariaDB",
    "mariadb": "MySQL/MariaDB",
    "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL",
    "ms-sql": "Microsoft SQL Server",
    "mssql": "Microsoft SQL Server",
    "oracle": "Oracle Database",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "memcached": "Memcached",
}


def _db_owner_classification(target_url, host):
    target = urlparse(str(target_url or ""))
    base_host = str(target.hostname or "").lower()
    host_text = str(host or "").strip().lower()

    if not host_text or not base_host:
        return "unknown"
    if host_text == base_host or host_text.endswith("." + base_host):
        return "first_party"

    try:
        ip_obj = ipaddress.ip_address(host_text)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return "private_network"
        return "public_ip"
    except Exception:
        return "third_party_or_unknown"


def _extract_database_assets_from_nmap_structured(target_url, nmap_structured, max_items=60):
    assets = []
    seen = set()

    for host in (nmap_structured or {}).get("hosts") or []:
        host_ip = str(host.get("host") or "").strip()
        for port_row in host.get("ports") or []:
            if str(port_row.get("state") or "").lower() != "open":
                continue

            port = int(port_row.get("port") or 0)
            service = str(port_row.get("service") or "").strip()
            product = str(port_row.get("product") or "").strip()
            version = str(port_row.get("version") or "").strip()
            protocol = str(port_row.get("protocol") or "tcp").strip() or "tcp"
            cpes = [str(c).strip() for c in (port_row.get("cpes") or []) if str(c).strip()]
            cpe_text = ", ".join(cpes[:2])

            blob = " ".join([service.lower(), product.lower(), cpe_text.lower()])
            db_type = ""
            for key, label in _DB_SERVICE_HINTS.items():
                if key in blob:
                    db_type = label
                    break
            if not db_type and port in _DB_PORT_HINTS:
                db_type = _DB_PORT_HINTS[port]
            if not db_type:
                continue

            key = (host_ip, port, protocol, db_type, version)
            if key in seen:
                continue
            seen.add(key)

            assets.append({
                "db_type": db_type,
                "host": host_ip,
                "port": port,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version or "desconocida",
                "cpe": cpe_text,
                "owner": _db_owner_classification(target_url, host_ip),
            })

            if len(assets) >= max_items:
                return assets

    return assets


def _build_database_exposure_rows(database_assets):
    if not database_assets:
        return []

    rows = [{
        "control": "Inventario técnico de BBDD expuestas",
        "status": "Detectado",
        "severity": "Alta",
        "description": "Se consolidó inventario de motores BBDD detectados por red con versión/host/puerto.",
        "evidence": (
            f"Motores detectados: {len(set(str(a.get('db_type') or '') for a in database_assets))} | "
            f"Instancias expuestas: {len(database_assets)}"
        ),
        "recommendation": "Priorizar control de acceso por red y parcheo en motores con versión obsoleta o desconocida.",
    }]

    for item in database_assets[:30]:
        rows.append({
            "control": f"BBDD expuesta: {item.get('db_type')}",
            "status": "Posible hallazgo",
            "severity": "Alta" if int(item.get("port", 0) or 0) in {1433, 1521, 27017, 3306, 5432, 6379, 9200, 11211} else "Media",
            "description": "Instancia de base de datos accesible desde superficie de red evaluada.",
            "evidence": (
                f"Host/IP: {item.get('host')} | Puerto: {item.get('port')}/{item.get('protocol')} | "
                f"Motor: {item.get('db_type')} | Producto: {item.get('product') or item.get('service') or '-'} | "
                f"Versión: {item.get('version') or 'desconocida'} | "
                f"Ownership: {item.get('owner')}"
                + (f" | CPE: {item.get('cpe')}" if item.get("cpe") else "")
            ),
            "recommendation": "Validar autenticación/cifrado, restringir orígenes y revisar exposición a Internet.",
        })

    return rows


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

    .bh-toolbox {
        margin: 0.6rem 0 0.9rem 0;
        padding: 0.8rem 0.85rem;
        border: 1px solid rgba(148, 163, 184, 0.14);
        border-radius: 14px;
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.7), rgba(10, 15, 22, 0.92));
    }

    .bh-toolbox-title {
        font-size: 0.78rem;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        color: #8ea0b8;
        margin-bottom: 0.55rem;
    }

    .bh-tool-pill-row {
        display: flex;
        flex-wrap: wrap;
        gap: 0.4rem;
    }

    .bh-tool-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.38rem;
        padding: 0.22rem 0.55rem;
        border-radius: 999px;
        font-size: 0.78rem;
        border: 1px solid rgba(148, 163, 184, 0.16);
        background: rgba(15, 23, 42, 0.75);
        color: #dbe7f3;
    }

    .bh-tool-dot {
        width: 0.42rem;
        height: 0.42rem;
        border-radius: 999px;
        display: inline-block;
    }

    .bh-tool-ok {
        background: #22c55e;
        box-shadow: 0 0 10px rgba(34, 197, 94, 0.45);
    }

    .bh-tool-miss {
        background: #f59e0b;
        box-shadow: 0 0 10px rgba(245, 158, 11, 0.35);
    }

    .bh-toolbox-hint {
        margin-top: 0.5rem;
        font-size: 0.72rem;
        color: #8ea0b8;
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

    external_tool_status = detect_external_web_tools()
    tool_pills = []
    for tool_name, label in [("katana", "Katana"), ("httpx", "HTTPX"), ("nuclei", "Nuclei")]:
        info = external_tool_status.get(tool_name) or {}
        dot_class = "bh-tool-ok" if info.get("available") else "bh-tool-miss"
        state_label = "listo" if info.get("available") else "no detectado"
        tool_pills.append(
            f'<span class="bh-tool-pill"><span class="bh-tool-dot {dot_class}"></span>{label}: {state_label}</span>'
        )

    detected_paths = [
        f"{name}: {(external_tool_status.get(name) or {}).get('source') or 'sin ruta'}"
        for name in ["katana", "httpx", "nuclei"]
        if (external_tool_status.get(name) or {}).get("available")
    ]
    st.markdown(
        (
            '<div class="bh-toolbox">'
            '<div class="bh-toolbox-title">Motores externos web</div>'
            f'<div class="bh-tool-pill-row">{"".join(tool_pills)}</div>'
            f'<div class="bh-toolbox-hint">{" | ".join(detected_paths) if detected_paths else "Sin motores externos accesibles desde esta sesión."}</div>'
            '</div>'
        ),
        unsafe_allow_html=True,
    )

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
        nmap_profile = "KALI_FULL" if _nmap_bin else "DEEP"
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

    if _looks_like_not_found_page(page):
        return True

    return False


def _looks_like_not_found_page(page):
    status = _safe_status_int(page.get("status_code"))
    if status == 404:
        return True

    html_text = " ".join([
        str(page.get("html", "")),
        str(page.get("rendered_html", "")),
        str((page.get("browser_runtime") or {}).get("html", "")),
    ])[:20000].lower()
    if not html_text:
        return False

    strong_not_found_markers = [
        "this page could not be found",
        "page not found",
        "página no encontrada",
        "pagina no encontrada",
        "cannot be found",
        "the page you are looking for",
    ]

    if not any(marker in html_text for marker in strong_not_found_markers):
        return False

    # Avoid false negatives on real login pages that still contain 404 words in scripts/assets.
    if has_auth_form_indicators(page) or _has_password_runtime_indicator(page):
        return False

    forms_count = len(page.get("forms") or [])
    url = str(page.get("final_url") or page.get("url") or "").lower()
    if forms_count > 0 and any(token in url for token in ["/login", "/signin", "/auth", "iniciar-sesion", "inicio-sesion"]):
        return False

    return True


def is_redirected_page(page):
    requested_url = str(page.get("url") or "").strip().rstrip("/")
    final_url = str(page.get("final_url") or requested_url).strip().rstrip("/")
    return bool(requested_url and final_url and requested_url != final_url)


def _is_static_resource_url(url):
    path = urlparse(str(url or "")).path.lower()
    static_exts = (
        ".js", ".css", ".map", ".json", ".xml", ".txt",
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    )
    return bool(path.endswith(static_exts))


def _looks_like_auth_gate_page(page):
    classification = str(page.get("classification", "")).lower()
    if classification in ["auth", "protected_redirect_to_auth"]:
        return True

    if has_auth_form_indicators(page):
        return True

    html_blobs = [
        str(page.get("html") or ""),
        str(page.get("rendered_html") or ""),
        str((page.get("browser_runtime") or {}).get("html") or ""),
    ]
    combined = "\n".join(blob for blob in html_blobs if blob).lower()
    if not combined:
        return False

    auth_markers = [
        "iniciar sesión",
        "iniciar sesion",
        "sign in",
        "log in",
        "login",
        "accede a tu cuenta",
        "type=\"password\"",
        "name=\"password\"",
        "name=\"username\"",
        "name=\"email\"",
    ]
    return any(marker in combined for marker in auth_markers)


def is_admin_redirect_to_auth(page):
    requested_url = str(page.get("url") or page.get("final_url") or "").lower()
    final_url = str(page.get("final_url") or requested_url).lower()
    classification = str(page.get("classification", "")).lower()

    admin_tokens = ["admin", "dashboard", "panel", "backoffice", "administrator"]
    requested_admin = any(token in requested_url for token in admin_tokens)

    if not requested_admin:
        return False

    if classification == "protected_redirect_to_auth":
        return True

    auth_tokens = ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion"]

    if is_redirected_page(page) and any(token in final_url for token in auth_tokens):
        return True

    return _looks_like_auth_gate_page(page)


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

    if _is_static_resource_url(url):
        return False

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
    classification = str(page.get("classification", "")).lower()
    url = str(page.get("final_url") or page.get("url") or "").lower()

    flattened_forms = str(forms).lower()
    flattened_runtime = str(runtime_inputs).lower()
    combined = f"{flattened_forms} {flattened_runtime}"

    has_password = "password" in combined or "contraseña" in combined
    has_user = any(token in combined for token in ["email", "correo", "usuario", "user", "login"])
    auth_tokens = ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion", "register", "registro", "signup", "session"]
    action_blob = " ".join(str(form.get("action") or "") for form in forms).lower()
    contextual_auth = (
        classification in ["auth", "registration"]
        or any(token in url for token in auth_tokens)
        or any(token in action_blob for token in auth_tokens)
    )
    return has_password and has_user and contextual_auth


def _has_password_runtime_indicator(page):
    runtime_inputs = page.get("browser_inputs") or (page.get("browser_runtime") or {}).get("inputs") or []
    flat = str(runtime_inputs).lower()
    return "password" in flat or "contraseña" in flat


def _is_verified_auth_login_page(page):
    if is_blocked_or_error_page(page):
        return False

    if _looks_like_not_found_page(page):
        return False

    status = _safe_status_int(page.get("status_code"))
    if status in {0, 404}:
        return False

    forms_count = len(page.get("forms") or [])
    classification = str(page.get("classification", "")).lower()
    url = str(page.get("final_url") or page.get("url") or "").lower()
    has_auth_path = any(token in url for token in ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion"])

    if has_auth_form_indicators(page):
        return True

    if forms_count > 0 and has_auth_path:
        return True

    if _has_password_runtime_indicator(page) and has_auth_path:
        return True

    # Keep explicit auth gates (401/403) but avoid generic/empty auth labels with no form evidence.
    if classification == "auth" and status in {401, 403}:
        return True

    return False


def build_auth_attack_pages(pages):
    auth_keywords = ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion", "session"]
    candidates = []
    seen = set()

    for page in pages or []:
        url = str(page.get("final_url") or page.get("url") or "").lower()
        classification = str(page.get("classification", "")).lower()
        ai_page_type = str((page.get("ai_context") or {}).get("page_type", "")).lower()

        if _is_static_resource_url(url):
            continue

        if is_admin_redirect_to_auth(page):
            continue

        # Keep admin candidates out of auth SQLi target set; they are tested in access control.
        if classification == "admin_candidate":
            continue

        is_candidate = (
            is_auth_attack_page(page)
            or ai_page_type == "auth"
            or any(keyword in url for keyword in auth_keywords)
        )

        if not is_candidate:
            continue

        if not _is_verified_auth_login_page(page):
            continue

        key = str(page.get("final_url") or page.get("url") or "")
        if key and key not in seen:
            seen.add(key)
            candidates.append(page)

    def _auth_priority(page):
        url = str(page.get("final_url") or page.get("url") or "").lower()
        classification = str(page.get("classification", "")).lower()

        if "/es/login" in url or "/en/login" in url or url.endswith("/login"):
            return (0, 0)
        if "login" in url or "signin" in url or "iniciar-sesion" in url or "inicio-sesion" in url:
            return (0, 1)
        if classification == "auth":
            return (1, 0)
        if classification == "registration" or "register" in url or "registro" in url or "signup" in url:
            return (2, 0)
        return (3, 0)

    return sorted(candidates, key=_auth_priority)


def _ensure_login_target_first(auth_targets, all_pages, auth_used_login_url, auth_status):
    targets = list(auth_targets or [])
    login_url = str(auth_used_login_url or "").strip()
    status = str(auth_status or "").strip()

    if not login_url or status not in {"Autenticado", "Indeterminado"}:
        return targets

    login_key = _canonical_surface_url(login_url)
    if not login_key:
        return targets

    # Reuse existing page object when possible.
    selected = None
    for page in all_pages or []:
        page_key = _canonical_surface_url(page.get("final_url") or page.get("url") or "")
        if page_key == login_key:
            selected = dict(page)
            break

    if selected is None:
        selected = {
            "url": login_url,
            "final_url": login_url,
            "classification": "auth",
            "status_code": 200,
            "forms": [],
        }

    # If forced login target has no forms/inputs, borrow evidence from equivalent auth pages.
    forms_count = len(selected.get("forms") or [])
    runtime_inputs = selected.get("browser_inputs") or (selected.get("browser_runtime") or {}).get("inputs") or []
    if forms_count == 0 and not runtime_inputs:
        auth_like_candidates = []
        for page in all_pages or []:
            if is_blocked_or_error_page(page) or _looks_like_not_found_page(page):
                continue
            page_url = str(page.get("final_url") or page.get("url") or "").lower()
            if not any(tok in page_url for tok in ["/login", "/signin", "iniciar-sesion", "inicio-sesion", "/auth"]):
                continue
            if has_auth_form_indicators(page) or _has_password_runtime_indicator(page):
                auth_like_candidates.append(page)

        if auth_like_candidates:
            best = auth_like_candidates[0]
            selected["forms"] = list(best.get("forms") or [])
            if best.get("browser_inputs"):
                selected["browser_inputs"] = list(best.get("browser_inputs") or [])
            if best.get("browser_runtime"):
                selected["browser_runtime"] = dict(best.get("browser_runtime") or {})

    selected["classification"] = str(selected.get("classification") or "auth")
    selected["auth_target_forced"] = True

    remaining = [
        p for p in targets
        if _canonical_surface_url(p.get("final_url") or p.get("url") or "") != login_key
    ]
    return [selected] + remaining


def is_generic_attack_page(page):
    url = str(page.get("final_url") or page.get("url") or "").lower()
    classification = str(page.get("classification", "")).lower()

    if _is_static_resource_url(url):
        return False

    if classification in ["error_disclosure_candidate", "server_error"] and _is_static_resource_url(url):
        return False

    if is_admin_redirect_to_auth(page):
        return False

    if classification == "protected_redirect_to_auth":
        return False

    # Login/registration with credentials fields must be attackable even if page text contains generic blockers.
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
    if classification in {"soft_404", "request_error", "static_resource"}:
        return False

    if _is_static_resource_url(url):
        return False

    if _looks_like_not_found_page(page):
        return False

    return True


def _is_auth_or_registration_url(url):
    path = urlparse(str(url or "")).path.lower()
    return any(token in path for token in [
        "/login", "/signin", "/auth", "/session",
        "/register", "/signup", "/registro", "crear-cuenta",
    ])


def _filter_verified_post_login_pages(pages, *, target_url="", auth_used_login_url=""):
    target_key = _canonical_surface_url(target_url)
    login_key = _canonical_surface_url(auth_used_login_url)
    filtered = []

    for page in pages or []:
        if not _is_meaningful_post_login_page(page):
            continue

        final_url = str(page.get("final_url") or page.get("url") or "").strip()
        final_key = _canonical_surface_url(final_url)
        classification = str(page.get("classification") or "").lower()

        if not final_key:
            continue
        if final_key == target_key or final_key == login_key:
            continue
        if classification in {"auth", "registration"}:
            continue
        if _is_auth_or_registration_url(final_url):
            continue

        filtered.append(page)

    return filtered


def _collect_post_login_candidate_endpoints(pages, max_items=30, *, target_url=""):
    endpoints = []
    seen = set()
    target_host = str(urlparse(str(target_url or "")).hostname or "").lower()
    static_ext = (
        ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    )

    valid_surface_keys = set()
    for page in pages or []:
        final_url = str(page.get("final_url") or page.get("url") or "").strip()
        if not final_url:
            continue
        if _safe_status_int(page.get("status_code")) in {0, 404}:
            continue
        if _looks_like_not_found_page(page):
            continue
        valid_surface_keys.add(_canonical_surface_url(final_url))

    def _is_noise_endpoint(raw):
        text = str(raw or "").strip()
        if not text:
            return True
        if not text.startswith(("http://", "https://")):
            return True
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return True
        if target_host and str(parsed.hostname or "").lower() != target_host:
            return True
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        if path.endswith(static_ext):
            return True
        if "_rsc=" in query:
            return True
        if _is_auth_or_registration_url(text):
            return True
        if text.lower() in {"unknown_or_api", "unknown", "n/a", "-"}:
            return True
        if any(tok in path for tok in ["/login", "/signin", "/auth", "/session"]) and any(
            tok in query for tok in ["redirect=", "next=", "returnurl=", "callbackurl="]
        ):
            return True
        return False

    def _add_endpoint(value, *, require_known_surface=False):
        text = str(value or "").strip()
        if not text or _is_noise_endpoint(text):
            return
        norm = _canonical_surface_url(text)
        if require_known_surface and norm not in valid_surface_keys:
            return
        if not norm or norm in seen:
            return
        seen.add(norm)
        endpoints.append(norm)

    for page in pages or []:
        if _looks_like_not_found_page(page):
            continue
        if _safe_status_int(page.get("status_code")) in {0, 404}:
            continue

        ai_context = page.get("ai_context") or {}
        runtime = page.get("browser_runtime") or {}
        for endpoint in (ai_context.get("candidate_endpoints") or []) + (runtime.get("candidate_endpoints") or []):
            # Runtime/API hints are only accepted if they match a verified discovered surface URL.
            _add_endpoint(endpoint, require_known_surface=True)
            if len(endpoints) >= max_items:
                return endpoints

        page_base = str(page.get("final_url") or page.get("url") or "")
        for form in (page.get("forms") or []):
            action = str(form.get("action") or "").strip()
            if action.startswith("/") and page_base:
                action = urljoin(page_base, action)
            _add_endpoint(action, require_known_surface=True)
            if len(endpoints) >= max_items:
                return endpoints

        classification = str(page.get("classification") or "").lower()
        if classification in {"api_candidate", "sensitive_candidate", "admin_candidate", "protected", "protected_redirect_to_auth"}:
            _add_endpoint(page.get("final_url") or page.get("url") or "")
            if len(endpoints) >= max_items:
                return endpoints

    return endpoints


def _collect_verified_http_events(target_url, events, *, max_items=80):
    target_host = str(urlparse(str(target_url or "")).hostname or "").lower()
    seen = set()
    verified = []

    static_ext = (
        ".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    )

    for event in events or []:
        method = str(event.get("method") or "").upper().strip()
        if method not in {"GET", "POST"}:
            continue

        final_url = str(event.get("final_url") or event.get("url") or "").strip()
        if not final_url.startswith(("http://", "https://")):
            continue

        parsed = urlparse(final_url)
        if target_host and str(parsed.hostname or "").lower() != target_host:
            continue

        status = int(event.get("status_code", 0) or 0)
        # Keep actionable/validated responses only.
        if status not in {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403}:
            continue

        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        if path.endswith(static_ext):
            continue
        if _is_auth_or_registration_url(final_url):
            continue
        if any(tok in query for tok in ["_rsc=", "redirect=", "next=", "returnurl=", "callbackurl="]):
            continue

        key = (method, _canonical_surface_url(final_url), status)
        if key in seen:
            continue
        seen.add(key)

        verified.append({
            "method": method,
            "url": _canonical_surface_url(final_url),
            "status_code": status,
            "duration_ms": int(event.get("duration_ms", 0) or 0),
            "content_type": str(event.get("content_type") or ""),
        })

        if len(verified) >= max_items:
            break

    return verified


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

        if any(token in url for token in ["admin", "dashboard", "panel", "backoffice", "administrator"]):
            page["classification"] = "protected_redirect_to_auth" if _looks_like_auth_gate_page(page) else "admin_candidate"
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


def _collect_cves_from_external_nuclei_findings(nuclei_findings):
    cves = []
    for finding in nuclei_findings or []:
        if not isinstance(finding, dict):
            continue

        matched_at = str(finding.get("matched_at") or "").strip()
        target_service = urlparse(matched_at).netloc or matched_at
        finding_severity = str(finding.get("severity") or "")
        finding_name = str(finding.get("name") or finding.get("template_id") or "Nuclei finding")
        circl_rows = finding.get("circl") if isinstance(finding.get("circl"), list) else []

        seen_ids = set()
        for circl_item in circl_rows:
            if not isinstance(circl_item, dict):
                continue
            cve_id = str(circl_item.get("id") or "").strip().upper()
            if not cve_id.startswith("CVE-") or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            cves.append({
                "id": cve_id,
                "score": float(circl_item.get("cvss") or 0) if str(circl_item.get("cvss") or "").strip() else 0,
                "severity": finding_severity,
                "description": str(circl_item.get("summary") or finding_name),
                "service": target_service,
                "version": "",
                "source": "nuclei-circl",
                "references": circl_item.get("references") or [],
                "likely_affected": True,
            })

        for cve_id in finding.get("cve_ids") or []:
            cve_id = str(cve_id or "").strip().upper()
            if not cve_id.startswith("CVE-") or cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            cves.append({
                "id": cve_id,
                "score": 0,
                "severity": finding_severity,
                "description": finding_name,
                "service": target_service,
                "version": "",
                "source": "nuclei",
                "references": [],
                "likely_affected": True,
            })

    return cves


def _dedupe_cves_by_best_score(cves):
    cve_best = {}
    for cve in cves or []:
        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            continue
        score = float(cve.get("score", 0) or 0)
        current = cve_best.get(cve_id)
        if current is None or score > float(current.get("score", 0) or 0):
            cve_best[cve_id] = dict(cve)
    return list(cve_best.values())


def _collect_cves_from_results_rows(results, max_items=80):
    cve_re = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    found = []
    seen = set()

    for row in results or []:
        if not isinstance(row, dict):
            continue
        blob = " | ".join([
            str(row.get("Control") or ""),
            str(row.get("Descripción") or ""),
            str(row.get("Evidencia") or ""),
        ])
        matches = cve_re.findall(blob)
        if not matches:
            continue

        sev_text = str(row.get("Severidad") or "")
        score = 0.0
        if sev_text == "Crítica":
            score = 9.0
        elif sev_text == "Alta":
            score = 7.5
        elif sev_text == "Media":
            score = 5.0
        elif sev_text == "Baja":
            score = 3.0

        service_hint = ""
        hint_match = re.search(r"https?://[^\s|]+", blob, re.IGNORECASE)
        if hint_match:
            try:
                service_hint = urlparse(hint_match.group(0)).netloc
            except Exception:
                service_hint = ""

        for token in matches:
            cve_id = str(token or "").strip().upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            found.append({
                "id": cve_id,
                "score": score,
                "severity": sev_text,
                "description": str(row.get("Descripción") or row.get("Control") or ""),
                "service": service_hint,
                "version": "",
                "source": "results-fallback",
                "references": [],
                "likely_affected": True,
            })
            if len(found) >= max_items:
                return found

    return found


def _collect_nmap_service_cves(nmap_structured, *, max_services=24, max_cves_per_service=10):
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

    if max_services:
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

        ranked = sorted(
            found,
            key=lambda x: float(x.get("score", 0) or 0),
            reverse=True,
        )

        # Keep CVEs likely affecting the detected version first; include very high-score tails.
        top = [x for x in ranked if bool(x.get("likely_affected", True))]
        if max_cves_per_service:
            top = top[:max_cves_per_service]
        if not top:
            top = [x for x in ranked if float(x.get("score", 0) or 0) >= 9.0][: max(3, max_cves_per_service // 2 if max_cves_per_service else 5)]

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
                "references": cve.get("references") or [],
                "likely_affected": bool(cve.get("likely_affected", True)),
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


def _build_cve_intel_rows(cves, summary):
    rows = []
    if not cves:
        return rows

    rows.append({
        "control": "Inteligencia CVE abierta (EPSS + KEV)",
        "status": "Detectado",
        "severity": "Informativa",
        "description": "Se enriquecieron CVEs con señales públicas de explotabilidad activa para priorización real.",
        "evidence": (
            f"CVEs: {summary.get('total', 0)} | "
            f"EPSS enriquecidos: {summary.get('epss_enriched', 0)} | "
            f"CISA KEV: {summary.get('kev_hits', 0)} | "
            f"Urgente/Alta/Media/Baja: "
            f"{summary.get('urgent', 0)}/{summary.get('high', 0)}/{summary.get('medium', 0)}/{summary.get('low', 0)}"
        ),
        "recommendation": "Priorizar primero CVEs KEV y EPSS alto para mitigación y validación de exposición.",
    })

    top = sorted(
        cves,
        key=lambda x: (
            1 if x.get("kev") else 0,
            float(x.get("epss", 0) or 0),
            float(x.get("score", 0) or 0),
        ),
        reverse=True,
    )[:25]

    for item in top:
        score = float(item.get("score", 0) or 0)
        epss = float(item.get("epss", 0) or 0)
        sev = _severity_from_cvss(score)
        cve_id = str(item.get("id") or "")
        service = str(item.get("service") or "-")
        rows.append({
            "control": f"Priorización CVE: {cve_id}",
            "status": "Posible hallazgo" if sev in {"Crítica", "Alta", "Media"} else "Detectado",
            "severity": sev,
            "description": "CVE priorizado por señal combinada CVSS + EPSS + KEV.",
            "evidence": (
                f"CVE: {cve_id} | Servicio: {service} | CVSS: {score:.1f} | "
                f"EPSS: {epss:.3f} | KEV: {'sí' if item.get('kev') else 'no'} | "
                f"Prioridad: {item.get('priority_tier', '-') } | "
                f"Afectación probable: {'sí' if item.get('likely_affected', True) else 'no'}"
            ),
            "recommendation": "Remediar por orden de prioridad (Urgente > Alta > Media > Baja) y validar exposición real.",
        })

    return rows


def _select_actionable_cves(cves):
    """Return CVEs with real operational priority for exploitation testing."""
    selected = []
    for cve in cves or []:
        score = float(cve.get("score", 0) or 0)
        epss = float(cve.get("epss", 0) or 0)
        kev = bool(cve.get("kev"))
        likely = bool(cve.get("likely_affected", True))
        source = str(cve.get("source") or "").lower()
        sev = str(cve.get("severity") or "").lower()

        # Keep only CVEs that are either actively exploited/likely exploitable,
        # and avoid weak low-relevance noise.
        if kev or epss >= 0.30:
            selected.append(cve)
            continue
        if score >= 7.0 and likely:
            selected.append(cve)
            continue
        if score >= 9.0:
            selected.append(cve)
            continue

        # Preserve CVEs discovered by external Nuclei/CIRCL pipeline even when
        # enrichment is partial (e.g., EPSS unavailable) to keep exploit workflow visible.
        if source in {"nuclei", "nuclei-circl", "results-fallback"} and sev in {"critical", "high", "medium", "alta", "media", "crítica", "critica"}:
            selected.append(cve)
            continue

    return selected


def _render_exploit_suggestions_panel(suggestions, *, title_suffix=""):
    if not suggestions:
        return

    def _is_generic_placeholder(text):
        value = str(text or "").strip().lower()
        if not value:
            return True
        generic_patterns = (
            "consultar cve",
            "consultar el aviso oficial del cve",
            "detalles del vector de ataque",
            "revisar referencias",
        )
        return any(pattern in value for pattern in generic_patterns)

    def _clean_text(text):
        value = str(text or "").strip()
        return "" if _is_generic_placeholder(value) else value

    def _collect_validation_commands(item):
        commands = []
        msf_hint = str(item.get("msf_hint") or "").strip()
        if msf_hint and not _is_generic_placeholder(msf_hint) and "searchsploit" not in msf_hint.lower():
            commands.append(msf_hint)
        for cmd in item.get("verification_commands") or []:
            cmd_text = str(cmd or "").strip()
            if cmd_text and "searchsploit" not in cmd_text.lower() and cmd_text not in commands:
                commands.append(cmd_text)
        return commands[:4]

    heading = "CVEs encontrados"
    if title_suffix:
        heading = f"{heading} {title_suffix}"

    st.markdown("---")
    st.subheader(f"{heading} ({len(suggestions)})")

    crit = sum(1 for s in suggestions if s.get("severity") == "critical")
    high = sum(1 for s in suggestions if s.get("severity") == "high")
    ai_used = sum(1 for s in suggestions if s.get("ai_used"))
    c1, c2, c3 = st.columns(3)
    c1.metric("CVEs analizados", len(suggestions))
    c2.metric("Críticos / Altos", f"{crit} / {high}")
    c3.metric("Enriquecidos con IA", ai_used)

    for sug in suggestions:
        sev = sug.get("severity", "info")
        sev_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")
        ai_badge = " [IA]" if sug.get("ai_used") else ""
        vector_txt = _clean_text(sug.get("vector")) or "N/D"
        title = f"{sev_color} {sug['cve_id']} | CVSS {sug['score']:.1f} | {vector_txt}{ai_badge}"

        with st.expander(title, expanded=(sev in ("critical", "high"))):
            service_label = " ".join(
                part for part in [str(sug.get("service", "") or "").strip(), str(sug.get("version", "") or "").strip()]
                if part
            ) or "-"
            technique = _clean_text(sug.get("technique"))
            remediation = str(sug.get("remediation") or "").strip()
            validation_cmds = _collect_validation_commands(sug)

            left, right = st.columns([1.05, 0.95])
            with left:
                st.markdown(f"**Afecta a:** {service_label} | **Familia:** {sug.get('family', '-')}")
                if remediation:
                    st.markdown(f"**Remediación:** {remediation}")
                if technique:
                    st.markdown(f"**Técnica:** {technique}")

                # ── Superficie afectada (ruta + DOM) ──────────────────
                surface_hits = sug.get("affected_surface") or []
                if surface_hits:
                    st.markdown("**Superficie afectada en el objetivo**")
                    for hit in surface_hits[:4]:
                        hit_url = str(hit.get("url") or "").strip()
                        hit_dom = str(hit.get("dom_target") or "").strip()
                        hit_ctx = str(hit.get("context") or "").strip()
                        confidence = float(hit.get("confidence", 0))
                        conf_badge = (
                            "🔴" if confidence >= 0.80 else
                            "🟠" if confidence >= 0.65 else
                            "🟡"
                        )
                        if hit_url:
                            st.markdown(f"{conf_badge} `{hit_url}`")
                        if hit_dom:
                            st.caption(f"DOM: {hit_dom}")
                        if hit_ctx:
                            st.caption(f"↳ {hit_ctx}")

                if validation_cmds:
                    st.markdown("**Validación**")
                    for cmd in validation_cmds[:3]:
                        st.code(cmd, language="bash")
                if sug.get("ai_analysis"):
                    ai = sug["ai_analysis"]
                    if ai.get("resumen"):
                        st.info(f"**IA:** {ai['resumen'][:220]}...")

            with right:
                if sug.get("description"):
                    st.caption(f"Descripción: {sug['description'][:220]}...")

                # ── PoC contextualizado con primera URL de superficie ──
                surface_hits = sug.get("affected_surface") or []
                best_surface = surface_hits[0] if surface_hits else None
                st.markdown("**PoC (entorno controlado)**")
                if best_surface and best_surface.get("url"):
                    st.caption(
                        f"Ruta objetivo: `{best_surface['url']}` "
                        f"— campo: `{best_surface.get('field') or '—'}`"
                    )
                if sug.get("poc"):
                    lang = "html" if str(sug["poc"]).strip().startswith("<") else "python"
                    st.code(sug["poc"][:1200], language=lang)
                else:
                    st.caption("No hay PoC local para este CVE en la base offline.")
                if sug.get("exploit_links"):
                    st.markdown("**Referencias**")
                    for link in (sug.get("exploit_links") or [])[:3]:
                        st.markdown(f"- {link}")


def _render_cve_findings_panel(*, cves, target_url, pages=None, enable_exploit_ai, exploit_ai_model, max_items=12):
    actionable = _select_actionable_cves(_dedupe_cves_by_best_score(cves or []))
    if not actionable:
        st.info("No se detectaron CVEs accionables para mostrar en esta ejecución.")
        return

    try:
        from scanner.exploit_suggester import build_exploit_suggestions

        suggestions = build_exploit_suggestions(
            cves=actionable[:max_items],
            target_url=target_url,
            ollama_model=exploit_ai_model,
            use_ollama=bool(enable_exploit_ai),
            max_ai_queries=5 if enable_exploit_ai else 0,
        )
    except Exception:
        suggestions = []

    # Enrich with specific routes and DOM context from the discovered surface
    if suggestions and pages:
        try:
            from scanner.surface_cve_mapper import enrich_suggestions_with_surface
            enrich_suggestions_with_surface(suggestions, pages, target_url=target_url)
        except Exception:
            pass

    if not suggestions:
        fallback = sorted(
            actionable,
            key=lambda x: float(x.get("score", 0) or 0),
            reverse=True,
        )[:max_items]
        suggestions = [
            {
                "cve_id": str(item.get("id") or ""),
                "score": float(item.get("score", 0) or 0),
                "severity": str(item.get("severity") or "info").lower(),
                "service": str(item.get("service") or ""),
                "version": str(item.get("version") or ""),
                "description": str(item.get("description") or ""),
                "family": "Análisis CVE",
                "technique": "Validación manual guiada",
                "vector": "Network",
                "poc": "# PoC no disponible en este contexto\n# Revisar referencias y validar en entorno controlado",
                "msf_hint": f"searchsploit {str(item.get('id') or '')}",
                "remediation": "Aplicar parche del proveedor y controles compensatorios.",
                "exploit_links": list(item.get("references") or [])[:4],
                "verification_commands": [f"searchsploit {str(item.get('id') or '')}"],
                "ai_analysis": None,
                "ai_used": False,
                "affected_surface": [],
            }
            for item in fallback
        ]
        # Enrich fallback as well
        if pages:
            try:
                from scanner.surface_cve_mapper import enrich_suggestions_with_surface
                enrich_suggestions_with_surface(suggestions, pages, target_url=target_url)
            except Exception:
                pass

    _render_exploit_suggestions_panel(suggestions, title_suffix="y explotabilidad")


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
    prefetched_web_chain = None
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
    if hasattr(auth_client, "enable_http_capture"):
        auth_client.enable_http_capture(True, limit=2000)
    auth_status = "No configurado"
    auth_used_login_url = ""
    auth_final_url = ""
    auth_cookies = {}
    auth_cookie_details = []
    auth_cookie_snapshot = {}
    auth_cookie_details_snapshot = []
    post_login_http_events = []

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
            katana_depth = 3 if is_aggressive_mode else 2
            katana_result = run_katana_discovery(
                target_url=target_url,
                depth=katana_depth,
                timeout=320,
            )
            katana_urls = katana_result.get("urls") or []
            httpx_active_urls, httpx_inspected, httpx_meta = verificar_endpoints_httpx(katana_urls)

            prefetched_web_chain = {
                "katana_urls": katana_urls,
                "httpx_active_urls": httpx_active_urls,
                "httpx_inspected": httpx_inspected,
                "nuclei_findings": [],
                "meta": {
                    "katana": {
                        "available": bool(katana_result.get("available")),
                        "executed": bool(katana_result.get("executed")),
                        "count": len(katana_urls),
                        "error": str(katana_result.get("error") or "")[:180],
                    },
                    "httpx": httpx_meta,
                    "nuclei": {"available": False, "executed": False, "count": 0},
                },
            }

            if httpx_meta.get("executed"):
                all_results.extend(normalize_results("Scope HTTPX", [{
                    "control": "Katana + HTTPX (scope activo)",
                    "status": "Detectado",
                    "severity": "Informativa",
                    "description": "Validación temprana de endpoints para alimentar discovery interno con rutas activas.",
                    "evidence": (
                        f"Katana URLs: {len(katana_urls)} | HTTPX inspeccionadas: {httpx_meta.get('count', 0)} | "
                        f"HTTPX activas: {httpx_meta.get('active', 0)}"
                    ),
                    "recommendation": "Priorizar rutas activas para pruebas automáticas y validación de controles por endpoint.",
                }]))

            if katana_result.get("rows"):
                all_results.extend(normalize_results("Katana Discovery", katana_result.get("rows") or []))

            discovery_scope_urls = list(dict.fromkeys((httpx_active_urls or []) + (katana_urls or [])))

            active_checks_budget = _compute_discovery_active_checks(
                is_aggressive_mode=is_aggressive_mode,
                seed_pages_count=len(crawler_pages or []),
            )
            discovery = discover_surface(
                target_url,
                client=auth_client,
                seed_pages=crawler_pages,
                max_active_checks=active_checks_budget,
                extra_candidate_urls=discovery_scope_urls,
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
                try:
                    auth_cookie_snapshot = dict(dict_from_cookiejar(auth_client.session.cookies))
                    auth_cookie_details_snapshot = _extract_cookie_details_from_jar(auth_client.session.cookies)
                except Exception:
                    auth_cookie_snapshot = {}
                    auth_cookie_details_snapshot = []
                break

            if status == "Indeterminado" and not chosen_indeterminate_client:
                chosen_indeterminate_client = attempt_client
                chosen_indeterminate_url = candidate

        if auth_status != "Autenticado" and chosen_indeterminate_client is not None:
            auth_client = chosen_indeterminate_client
            auth_status = "Indeterminado"
            auth_used_login_url = chosen_indeterminate_url
            try:
                auth_cookie_snapshot = dict(dict_from_cookiejar(auth_client.session.cookies))
                auth_cookie_details_snapshot = _extract_cookie_details_from_jar(auth_client.session.cookies)
            except Exception:
                auth_cookie_snapshot = {}
                auth_cookie_details_snapshot = []

        # If auth appears successful (or plausible), run post-auth crawl/discovery to expand protected scope.
        if auth_status in ["Autenticado", "Indeterminado"]:
            history_start_idx = len(getattr(auth_client, "request_history", []) or [])
            with st.spinner("Sesión establecida. Ejecutando recrawl post-login para descubrir superficie autenticada..."):
                try:
                    pre_auth_surface_keys = {
                        _canonical_surface_url(page.get("final_url") or page.get("url"))
                        for page in (pages or [])
                    }
                    pre_auth_surface_keys.discard("")

                    post_auth_pages, _ = crawl_site(target_url, max_pages=None, client=auth_client)
                    if auth_final_url and _canonical_surface_url(auth_final_url) != _canonical_surface_url(target_url):
                        landing_pages, _ = crawl_site(auth_final_url, max_pages=None, client=auth_client)
                        post_auth_pages = dedupe_pages_by_url((post_auth_pages or []) + (landing_pages or []))

                    for page in post_auth_pages or []:
                        page["discovery_context"] = "post_login"
                        page_key = _canonical_surface_url(page.get("final_url") or page.get("url"))
                        page["is_new_post_login"] = bool(page_key and page_key not in pre_auth_surface_keys)

                    # Probe only authenticated routes that were actually observed in HTML/forms/runtime.
                    _dynamic_post_login_hints = _extract_post_login_route_hints(target_url, post_auth_pages, max_hints=80)
                    _parsed_origin = urlparse(target_url)
                    _origin_base = f"{_parsed_origin.scheme}://{_parsed_origin.netloc}"
                    _post_auth_baseline = get_soft404_baseline(auth_client, _origin_base)
                    _existing_post_keys = {
                        _canonical_surface_url(p.get("final_url") or p.get("url"))
                        for p in post_auth_pages
                    }
                    for _hint_item in list(dict.fromkeys(_dynamic_post_login_hints)):
                        _hint_url = _hint_item if str(_hint_item).startswith("http") else (_origin_base + str(_hint_item))
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
                            _hint_final_url = str(_hint_resp.url or _hint_url)
                            _hint_classification = classify_discovery_url(
                                _hint_url,
                                _hint_final_url,
                                _hint_resp,
                                baseline=_post_auth_baseline,
                            )
                            post_auth_pages.append({
                                "url": _hint_url,
                                "final_url": _hint_final_url,
                                "status_code": _hint_status,
                                "content_type": _hint_resp.headers.get("Content-Type", ""),
                                "html": _hint_html,
                                "forms": [],
                                "classification": _hint_classification,
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
                                    landing_final_url = str(landing_response.url or auth_final_url)
                                    post_auth_pages.append({
                                        "url": auth_final_url,
                                        "final_url": landing_final_url,
                                        "status_code": int(getattr(landing_response, "status_code", 0) or 0),
                                        "content_type": landing_content_type,
                                        "html": landing_html,
                                        "forms": [],
                                        "classification": classify_discovery_url(
                                            auth_final_url,
                                            landing_final_url,
                                            landing_response,
                                            baseline=_post_auth_baseline,
                                        ),
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

                    protected_hint_tokens = ["admin", "dashboard", "backoffice", "private"]
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

            raw_post_login_http_events = (getattr(auth_client, "request_history", []) or [])[history_start_idx:]
            post_login_http_events = _collect_verified_http_events(
                target_url,
                raw_post_login_http_events,
                max_items=80,
            )
            get_count = sum(1 for e in post_login_http_events if e.get("method") == "GET")
            post_count = sum(1 for e in post_login_http_events if e.get("method") == "POST")

            all_results.extend(normalize_results("Autenticación", [{
                "control": "Intercepción HTTP autenticada (GET/POST)",
                "status": "Detectado" if post_login_http_events else "No evidenciado",
                "severity": "Informativa",
                "description": "Se registró tráfico HTTP autenticado para validar endpoints reales observados en sesión.",
                "evidence": (
                    f"Eventos verificados: {len(post_login_http_events)} | "
                    f"GET: {get_count} | POST: {post_count}"
                ),
                "recommendation": "Usar estos endpoints verificados para pruebas de autorización y replay de sesión en entorno autorizado.",
            }]))

            for event in post_login_http_events[:15]:
                all_results.extend(normalize_results("Autenticación", [{
                    "control": f"HTTP autenticado {event.get('method')} {event.get('url')}",
                    "status": "Comprobado",
                    "severity": "Informativa",
                    "description": "Petición autenticada observada en tráfico real de sesión.",
                    "evidence": (
                        f"HTTP {event.get('status_code')} | "
                        f"Duración: {event.get('duration_ms', 0)} ms | "
                        f"Content-Type: {event.get('content_type') or '-'}"
                    ),
                    "recommendation": "Priorizar esta ruta en validación de control de acceso por rol y pruebas de sesión.",
                }]))

            all_results.extend(normalize_results("Autenticación", build_login_db_intel_rows(
                raw_events=raw_post_login_http_events,
                verified_events=post_login_http_events,
            )))

        try:
            final_auth_cookies = dict(dict_from_cookiejar(auth_client.session.cookies))
            final_auth_cookie_details = _extract_cookie_details_from_jar(auth_client.session.cookies)
            auth_cookies = _merge_cookie_maps(auth_cookie_snapshot, final_auth_cookies)
            auth_cookie_details = _merge_cookie_details(auth_cookie_details_snapshot, final_auth_cookie_details)
        except Exception:
            auth_cookies = dict(auth_cookie_snapshot or {})
            auth_cookie_details = list(auth_cookie_details_snapshot or [])

        all_results.extend(normalize_results("Autenticación", [{
            "control": "Captura de cookies de sesión",
            "status": "Detectado" if auth_cookie_details else "No evidenciado",
            "severity": "Media" if auth_cookie_details else "Informativa",
            "description": "Se capturó metadata de cookies de sesión para validación controlada de secuestro de sesión.",
            "evidence": (
                f"Cookies capturadas: {len(auth_cookie_details)} | "
                f"Nombres: {', '.join([c.get('name', '') for c in auth_cookie_details[:8]]) or 'ninguna'}"
            ),
            "recommendation": "Validar flags Secure/HttpOnly/SameSite y reuso de sesión solo en entorno autorizado.",
        }]))
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
    if prefetched_web_chain:
        discovered_urls = list(dict.fromkeys(discovered_urls + (prefetched_web_chain.get("httpx_active_urls") or [])))

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
    nessus_structured = {"scan_id": None, "vulnerabilities": []}
    _all_cves_found: list = []  # flat CVE list for exploit suggester
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
        if parity_enabled or str(nmap_profile or "").upper() in {"DEEP", "AGGRESSIVE", "KALI_FULL"}:
            with st.spinner("Correlando CVEs por servicios/versiones detectados por Nmap..."):
                nmap_cve_rows, nmap_cves = _collect_nmap_service_cves(
                    nmap_structured,
                    max_services=18 if parity_enabled else 12,
                    max_cves_per_service=10,
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
        _all_cves_found = _dedupe_cves_by_best_score(_all_cves_found)

        try:
            with st.spinner("Enriqueciendo CVEs con inteligencia pública (EPSS/KEV)..."):
                _all_cves_found, _cve_intel_summary = enrich_cves_with_free_intel(
                    _all_cves_found,
                    timeout=7.0,
                )
            all_results.extend(normalize_results("Inteligencia CVE abierta", _build_cve_intel_rows(
                _all_cves_found,
                _cve_intel_summary,
            )))

            actionable = _select_actionable_cves(_all_cves_found)
            all_results.extend(normalize_results("Inteligencia CVE abierta", [{
                "control": "Filtro de CVEs accionables",
                "status": "Comprobado",
                "severity": "Informativa",
                "description": "Se filtran CVEs a los realmente priorizables para validación ofensiva.",
                "evidence": (
                    f"CVEs totales enriquecidos: {len(_all_cves_found)} | "
                    f"CVEs accionables: {len(actionable)}"
                ),
                "recommendation": "Concentrar pruebas en KEV, EPSS alto y CVSS>=7 con afectación probable.",
            }]))
            _all_cves_found = actionable
        except Exception:
            all_results.extend(normalize_results("Inteligencia CVE abierta", [{
                "control": "Inteligencia CVE abierta (EPSS + KEV)",
                "status": "No probado",
                "severity": "Informativa",
                "description": "No se pudo completar el enriquecimiento externo de CVEs.",
                "evidence": traceback.format_exc()[:260],
                "recommendation": "Verificar salida a Internet/proxy y reintentar para mejorar priorización.",
            }]))

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

    # Optional external OSS cascade (Katana -> Feroxbuster -> Nmap -> Nuclei) with strict dedup.
    try:
        external_auth_params = _build_external_auth_params(auth_status, auth_cookies)
        external_fuzz_wordlist = str(os.getenv("EXTERNAL_FUZZ_WORDLIST", "") or "").strip()
        with st.spinner("Ejecutando pipeline externo (Katana/Fuzzing/HTTPX/Nuclei)..."):
            external_pipeline = run_external_tools_pipeline(
                target_url=target_url,
                existing_results=all_results,
                depth=free_scanner_depth,
                nmap_path=nmap_bin or "",
                run_nmap_stage=not bool(enable_nmap),
                prefetched_web_chain=prefetched_web_chain,
                auth_params=external_auth_params,
                fuzz_wordlist_path=external_fuzz_wordlist,
            )
        external_rows = external_pipeline.get("rows") or []
        if external_rows:
            all_results.extend(normalize_results("Pipeline externo OSS", external_rows))

        external_nuclei_cves = _collect_cves_from_external_nuclei_findings(
            external_pipeline.get("nuclei_findings") or []
        )
        if external_nuclei_cves:
            _all_cves_found = _dedupe_cves_by_best_score(_all_cves_found + external_nuclei_cves)
            _all_cves_found = _select_actionable_cves(_all_cves_found) or _all_cves_found
    except Exception:
        all_results.extend(normalize_results("Pipeline externo OSS", [{
            "control": "Orquestación Katana/Ferox/Nmap/Nuclei",
            "status": "No probado",
            "severity": "Informativa",
            "description": "No se pudo ejecutar el pipeline externo en esta ejecución.",
            "evidence": traceback.format_exc()[:260],
            "recommendation": "Verificar binarios locales y PATH para herramientas externas.",
        }]))

    # Optional Kali-style quick fingerprint stage (WhatWeb/WAFW00F when available).
    try:
        kali_rows = run_kali_quick_fingerprint(target_url)
        if kali_rows:
            all_results.extend(normalize_results("Pipeline Kali", kali_rows))
    except Exception:
        all_results.extend(normalize_results("Pipeline Kali", [{
            "control": "Fingerprint Kali rápido",
            "status": "No probado",
            "severity": "Informativa",
            "description": "No se pudo ejecutar el fingerprint rápido estilo Kali.",
            "evidence": traceback.format_exc()[:260],
            "recommendation": "Verificar disponibilidad local de whatweb/wafw00f y permisos de ejecución.",
        }]))

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

    database_assets = _extract_database_assets_from_nmap_structured(target_url, nmap_structured)
    if database_assets:
        all_results.extend(normalize_results("Inteligencia BBDD", _build_database_exposure_rows(database_assets)))

    all_results.extend(normalize_results("Procedimientos Kali", build_kali_procedure_rows(
        target_url=target_url,
        has_auth=auth_status in {"Autenticado", "Indeterminado"},
        verified_events=post_login_http_events,
        db_assets=database_assets,
    )))

    auth_attack_pages = dedupe_pages_by_url(build_auth_attack_pages(pages))
    auth_attack_pages = _ensure_login_target_first(
        auth_targets=auth_attack_pages,
        all_pages=pages,
        auth_used_login_url=auth_used_login_url,
        auth_status=auth_status,
    )
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
        "auth_cookie_details": auth_cookie_details,
        "post_login_http_events": post_login_http_events,
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
        "database_assets": database_assets,
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
    auth_cookie_details = state.get("auth_cookie_details") or []
    database_assets = state.get("database_assets") or []
    post_login_http_events = state.get("post_login_http_events") or []
    use_auth = bool(state.get("use_auth", False))

    login_pages = list(auth_attack_pages)
    registration_pages = [
        p for p in pages
        if _safe_status_int(p.get("status_code")) not in {0, 404}
        and str(p.get("classification", "")).lower() not in {"soft_404", "request_error"}
        and (
            str(p.get("classification", "")).lower() == "registration"
            or any(
                token in str(p.get("final_url") or p.get("url") or "").lower()
                for token in ["/register", "/signup", "/registro", "crear-cuenta"]
            )
        )
    ]
    registration_pages = dedupe_pages_by_url(registration_pages)

    api_pages = [p for p in pages if p.get("classification") in ["api_candidate"]]
    admin_pages = [p for p in pages if p.get("classification") in ["admin_candidate"]]
    protected_pages = [p for p in pages if p.get("classification") in ["protected", "protected_redirect_to_auth"]]
    post_login_pages = [
        p for p in pages
        if str(p.get("discovery_context", "")).lower() == "post_login"
    ]
    verified_post_login = _filter_verified_post_login_pages(
        post_login_pages,
        target_url=state.get("target_url", ""),
        auth_used_login_url=auth_used_login_url,
    )
    post_login_new = [p for p in verified_post_login if p.get("is_new_post_login")]
    display_post_login = post_login_new or verified_post_login
    traffic_post_login_urls = list(dict.fromkeys([
        str(e.get("url") or "").strip()
        for e in (post_login_http_events or [])
        if str(e.get("url") or "").strip()
    ]))
    effective_post_login_count = len(display_post_login) if display_post_login else len(traffic_post_login_urls)
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
    post_login_endpoint_hints = _collect_post_login_candidate_endpoints(
        display_post_login,
        target_url=state.get("target_url", ""),
    )

    st.markdown("---")
    st.markdown("### Fase 1 completada — Superficie descubierta")

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Páginas totales", len(pages))
    c2.metric("Páginas atacables", len(attackable_pages))
    c3.metric("Logins / registro", len(login_pages) + len(registration_pages))
    c4.metric("APIs candidatas", len(api_pages))
    c5.metric("Admin / protegidas", len(admin_pages) + len(protected_pages))
    c6.metric("BBDD expuestas", len(database_assets))

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

    if use_auth and (auth_cookie_details or auth_cookie_names):
        _render_cookie_capture_panel(auth_cookie_details, state.get("auth_cookies") or {})

    if login_pages:
        st.markdown("**Logins y rutas de autenticación detectadas:**")
        for p in login_pages[:15]:
            url = p.get("final_url") or p.get("url") or ""
            classification = p.get("classification", "")
            forms_count = len(p.get("forms") or [])
            st.markdown(f"- `{url}` — clasificación: **{classification}** — formularios: **{forms_count}**")
    else:
        st.info("No se detectaron rutas de autenticación. Los ataques de login no se ejecutarán.")

    if registration_pages:
        st.markdown("**Rutas de registro detectadas:**")
        for p in registration_pages[:10]:
            st.markdown(f"- `{p.get('final_url') or p.get('url') or ''}`")

    if api_pages:
        st.markdown("**APIs candidatas:**")
        for p in api_pages[:10]:
            st.markdown(f"- `{p.get('final_url') or p.get('url', '')}`")

    if admin_pages:
        st.markdown("**Rutas administrativas:**")
        for p in admin_pages[:10]:
            st.markdown(f"- `{p.get('final_url') or p.get('url', '')}`")

    if database_assets:
        with st.expander("Ver inventario técnico de BBDD expuestas", expanded=False):
            for db in database_assets[:25]:
                st.markdown(
                    f"- **{db.get('db_type', '-') }** `{db.get('host','-')}:{db.get('port','-')}/{db.get('protocol','tcp')}` "
                    f"— versión: **{db.get('version','desconocida')}** "
                    f"— owner: **{db.get('owner','unknown')}**"
                )
            if len(database_assets) > 25:
                st.caption(f"… y {len(database_assets) - 25} más")

    if use_auth:
        st.markdown(
            f"**Cobertura post-login:** {effective_post_login_count} URL(s) relevantes en sesión autenticada | "
            f"Rutas protegidas/candidatas: {len(post_login_protected)} | "
            f"Endpoints candidatos: {len(post_login_endpoint_hints)} | "
            f"Tráfico GET/POST verificado: {len(post_login_http_events)}"
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
        if post_login_endpoint_hints:
            with st.expander("Ver endpoints candidatos descubiertos tras login", expanded=False):
                for endpoint in post_login_endpoint_hints:
                    st.markdown(f"- `{endpoint}`")
        if post_login_http_events:
            with st.expander("Ver tráfico autenticado interceptado (GET/POST)", expanded=False):
                traffic_df = pd.DataFrame(post_login_http_events[:30])
                st.dataframe(traffic_df, width="stretch")
        elif traffic_post_login_urls:
            with st.expander("Ver URLs inferidas por tráfico autenticado", expanded=False):
                for endpoint in traffic_post_login_urls[:30]:
                    st.markdown(f"- `{endpoint}`")


def _render_auth_post_login_summary(*, use_auth, auth_status, auth_used_login_url, auth_final_url, auth_cookies, auth_cookie_details, post_login_http_events, pages, all_results, target_url=""):
    if not use_auth:
        return

    st.markdown("### Estado de autenticación y cobertura post-login")

    cookie_names = sorted((auth_cookies or {}).keys())
    if auth_cookie_details:
        cookie_names = sorted({str(item.get("name") or "") for item in auth_cookie_details if item.get("name")})
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
    ]
    verified_post_login = _filter_verified_post_login_pages(
        post_login_pages,
        target_url=target_url,
        auth_used_login_url=auth_used_login_url,
    )
    post_login_new = [p for p in verified_post_login if p.get("is_new_post_login")]
    display_post_login = post_login_new or verified_post_login
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
    post_login_endpoint_hints = _collect_post_login_candidate_endpoints(
        display_post_login,
        target_url=target_url,
    )

    st.caption(
        f"URLs post-login descubiertas: {len(display_post_login)} | "
        f"Rutas protegidas/candidatas: {len(protected_post_login)} | "
        f"Endpoints candidatos: {len(post_login_endpoint_hints)}"
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

    if post_login_endpoint_hints:
        with st.expander("Endpoints candidatos descubiertos en sesión autenticada", expanded=False):
            for endpoint in post_login_endpoint_hints:
                st.markdown(f"- `{endpoint}`")

    if post_login_http_events:
        with st.expander("Tráfico autenticado interceptado (GET/POST)", expanded=False):
            st.dataframe(pd.DataFrame((post_login_http_events or [])[:40]), width="stretch")

    _render_cookie_capture_panel(auth_cookie_details, auth_cookies)

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


def _render_database_exposure_summary(*, database_assets, candidate_targets):
    assets = list(database_assets or [])
    db_candidates = [
        t for t in (candidate_targets or [])
        if str(t.get("kind") or "").strip().lower() == "database-service"
    ]

    if not assets and not db_candidates:
        return

    st.markdown("### Inteligencia de bases de datos detectadas")
    st.caption(
        f"Instancias BBDD detectadas: {len(assets)} | "
        f"Targets ofensivos derivados: {len(db_candidates)}"
    )

    if assets:
        table_rows = []
        for item in assets[:40]:
            table_rows.append({
                "motor": item.get("db_type") or "",
                "host": item.get("host") or "",
                "puerto": item.get("port") or "",
                "version": item.get("version") or "desconocida",
                "owner": item.get("owner") or "unknown",
                "producto": item.get("product") or item.get("service") or "",
            })
        st.dataframe(pd.DataFrame(table_rows), width="stretch")

    if db_candidates:
        with st.expander("Targets BBDD priorizados para validación ofensiva", expanded=False):
            for target in db_candidates[:30]:
                st.markdown(
                    f"- `{target.get('target')}` — score: **{target.get('priority_score', '-') }** "
                    f"— owner: **{target.get('owner', 'unknown')}** — {target.get('reason', '')}"
                )
            if len(db_candidates) > 30:
                st.caption(f"… y {len(db_candidates) - 30} más")


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

    st.markdown("### CVEs detectados (priorizados y explotables)")
    _render_cve_findings_panel(
        cves=state.get("all_cves_found") or [],
        target_url=target_url,
        pages=pages,
        enable_exploit_ai=bool(st.session_state.get("_enable_exploit_ai", True)),
        exploit_ai_model=str(st.session_state.get("_exploit_ai_model", "llama3") or "llama3"),
    )

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
                    runtime_inputs = p.get("browser_inputs") or (p.get("browser_runtime") or {}).get("inputs") or []
                    runtime_n = len(runtime_inputs)
                    if forms_n > 0:
                        evidence_tag = f"forms: {forms_n}"
                    elif runtime_n > 0:
                        evidence_tag = f"inputs runtime: {runtime_n}"
                    elif p.get("auth_target_forced"):
                        evidence_tag = "login verificado"
                    else:
                        evidence_tag = "evidencia dinámica no disponible"
                    st.markdown(f"- `{u}` &nbsp; <span style='color:#ffadad;font-size:0.85em'>{evidence_tag}</span>", unsafe_allow_html=True)
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
    _cves_fallback_from_results = _collect_cves_from_results_rows(all_results)
    if _cves_fallback_from_results:
        _cves_for_exploits = _dedupe_cves_by_best_score(_cves_for_exploits + _cves_fallback_from_results)
    _exploit_ai_enabled = bool(st.session_state.get("_enable_exploit_ai", True))
    _exploit_ai_model = str(st.session_state.get("_exploit_ai_model", "llama3") or "llama3")

    if _cves_for_exploits and _exploit_ai_enabled:
        try:
            from scanner.exploit_suggester import build_exploit_suggestions
            with st.spinner("Agente IA analizando CVEs y generando propuestas de exploits..."):
                exploit_suggestions = build_exploit_suggestions(
                    cves=_cves_for_exploits,
                    target_url=target_url,
                    ollama_model=_exploit_ai_model,
                    use_ollama=True,
                    max_ai_queries=5,
                )
            # Enrich with surface context (route + DOM)
            _phase2_pages = state.get("pages") or pages or []
            if exploit_suggestions and _phase2_pages:
                try:
                    from scanner.surface_cve_mapper import enrich_suggestions_with_surface
                    enrich_suggestions_with_surface(exploit_suggestions, _phase2_pages, target_url=target_url)
                except Exception:
                    pass
            st.session_state["last_exploit_suggestions"] = exploit_suggestions

            if exploit_suggestions:
                _render_exploit_suggestions_panel(
                    exploit_suggestions,
                    title_suffix=f"— propuesta de exploits ({'IA' if any(s.get('ai_used') for s in exploit_suggestions) else 'offline'})",
                )
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
        auth_cookie_details=state.get("auth_cookie_details") or [],
        post_login_http_events=state.get("post_login_http_events") or [],
        pages=pages,
        all_results=all_results,
        target_url=state.get("target_url", ""),
    )

    _render_database_exposure_summary(
        database_assets=state.get("database_assets") or [],
        candidate_targets=state.get("candidate_targets") or [],
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
            auth_cookie_details=state.get("auth_cookie_details") or [],
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
