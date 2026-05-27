import re
from collections import defaultdict
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from scanner.http_client import HttpClient


API_HINTS = [
    "/api",
    "/graphql",
    "/v1/",
    "/v2/",
    "/v3/",
    "/rest/",
    "/swagger",
    "/openapi",
    "/api-docs",
]

ENDPOINT_REGEX = re.compile(
    r"(?:https?://[^\s\"'<>]+|/[a-zA-Z0-9_\-./?=&%]+)",
    re.IGNORECASE,
)


def _looks_like_api_endpoint(value: str) -> bool:
    lower = str(value or "").lower()
    return any(hint in lower for hint in API_HINTS)


def _same_host(url_a: str, url_b: str) -> bool:
    parsed_a = urlparse(str(url_a or ""))
    parsed_b = urlparse(str(url_b or ""))
    if not parsed_a.scheme or not parsed_b.scheme:
        return False
    if parsed_a.scheme != parsed_b.scheme:
        return False
    if parsed_a.hostname != parsed_b.hostname:
        return False
    port_a = parsed_a.port or (443 if parsed_a.scheme == "https" else 80)
    port_b = parsed_b.port or (443 if parsed_b.scheme == "https" else 80)
    return port_a == port_b


def _add_endpoint(found: dict, endpoint: str, source: str):
    normalized = str(endpoint or "").strip()
    if not normalized:
        return
    found[normalized].add(source)


def _add_endpoint_if_in_scope(found: dict, page_url: str, endpoint: str, source: str):
    normalized = str(endpoint or "").strip()
    if not normalized:
        return
    candidate = urljoin(page_url, normalized)
    if not _same_host(page_url, candidate):
        return
    _add_endpoint(found, candidate, source)


def _extract_from_html(page_url: str, html: str, found: dict, js_candidates: set):
    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception:
        return

    for tag in soup.find_all(["a", "link", "script", "iframe", "img", "source", "form"]):
        candidates = []
        for attr in ["href", "src", "action", "data-url", "data-endpoint", "data-api", "data-href"]:
            value = tag.get(attr)
            if value:
                candidates.append(value)

        for raw in candidates:
            absolute = urljoin(page_url, raw)
            if _looks_like_api_endpoint(absolute):
                _add_endpoint_if_in_scope(found, page_url, absolute, "html-link")

            if absolute.lower().endswith(".js") and _same_host(page_url, absolute):
                js_candidates.add(absolute)


def _extract_from_text_blob(page_url: str, text: str, found: dict):
    for match in ENDPOINT_REGEX.findall(str(text or "")):
        candidate = urljoin(page_url, match)
        if _looks_like_api_endpoint(candidate):
            _add_endpoint_if_in_scope(found, page_url, candidate, "html-js-snippet")


def _extract_from_runtime(page: dict, found: dict):
    page_url = str(page.get("final_url") or page.get("url") or "")
    runtime = page.get("browser_runtime") or {}

    for endpoint in runtime.get("candidate_endpoints") or []:
        if _looks_like_api_endpoint(endpoint):
            _add_endpoint_if_in_scope(found, page_url, endpoint, "runtime-candidate")

    for event in runtime.get("network_events") or []:
        endpoint = str(event.get("url") or "")
        if _looks_like_api_endpoint(endpoint):
            _add_endpoint_if_in_scope(found, page_url, endpoint, "runtime-network")


def _extract_from_pages(pages, found: dict, js_candidates: set):
    for page in pages or []:
        page_url = str(page.get("final_url") or page.get("url") or "")
        if not page_url:
            continue

        html_blobs = [
            page.get("html") or "",
            page.get("rendered_html") or "",
            (page.get("browser_runtime") or {}).get("html") or "",
        ]

        for blob in html_blobs:
            if not blob:
                continue
            _extract_from_html(page_url, blob, found, js_candidates)
            _extract_from_text_blob(page_url, blob, found)

        _extract_from_runtime(page, found)


def _extract_from_js(client, js_urls: list, found: dict, max_js_fetch: int = 6):
    for js_url in js_urls[:max_js_fetch]:
        try:
            response = client.get(js_url, timeout=8)
        except Exception:
            continue

        if int(getattr(response, "status_code", 0) or 0) >= 400:
            continue

        text = str(getattr(response, "text", "") or "")
        if not text:
            continue

        for match in ENDPOINT_REGEX.findall(text):
            absolute = urljoin(js_url, match)
            if _looks_like_api_endpoint(absolute):
                _add_endpoint(found, absolute, "js-static")


def _probe_common_paths(client, url: str, found: dict):
    common_api_paths = [
        "api/",
        "api/v1/",
        "api/v2/",
        "graphql",
        "swagger-ui.html",
        "v3/api-docs",
        "openapi.json",
        "openapi.yaml",
    ]

    base = url.rstrip("/") + "/"
    for path in common_api_paths:
        target = urljoin(base, path)
        try:
            response = client.get(target, timeout=8)
        except Exception:
            continue

        status = int(getattr(response, "status_code", 0) or 0)
        if status in [200, 401, 403]:
            _add_endpoint(found, f"{target} [{status}]", "active-probe")


def scan_api_discovery(url: str, pages, http_client=None):
    client = http_client or HttpClient()
    results = []
    discovered = defaultdict(set)
    js_candidates = set()

    _extract_from_pages(pages, discovered, js_candidates)
    _extract_from_js(client, sorted(js_candidates), discovered)
    _probe_common_paths(client, url, discovered)

    if discovered:
        post_login_count = 0
        for page in pages or []:
            if str(page.get("discovery_context", "")).lower() == "post_login":
                post_login_count += 1

        evidence_items = []
        for endpoint, sources in list(discovered.items())[:25]:
            source_txt = ",".join(sorted(sources))
            evidence_items.append(f"{endpoint} ({source_txt})")

        results.append({
            "control": "Descubrimiento de API",
            "status": "Detectado",
            "severity": "Media",
            "description": "Se detectaron rutas API por HTML, runtime browser, análisis estático JS y probing activo.",
            "evidence": (
                f"Total endpoints: {len(discovered)} | "
                f"Páginas post-login analizadas: {post_login_count} | "
                + " | ".join(evidence_items)
            ),
            "recommendation": "Revisar autenticación, autorización por objeto (BOLA/IDOR), rate limiting y documentación API expuesta.",
        })
    else:
        results.append({
            "control": "Descubrimiento de API",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron rutas API comunes en el alcance analizado.",
            "evidence": "Sin rutas API identificadas por HTML, runtime, JS estático ni probing activo.",
            "recommendation": "Validar manualmente APIs internas o autenticadas y repetir tras login válido.",
        })

    return results