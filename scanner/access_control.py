import re
import logging
from difflib import SequenceMatcher
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient


logger = logging.getLogger(__name__)


SENSITIVE_ENDPOINTS = [
    "/admin", "/administrator", "/dashboard", "/management",
    "/actuator", "/actuator/env", "/actuator/beans", "/actuator/metrics",
    "/actuator/mappings", "/actuator/httptrace", "/actuator/logfile",
    "/api/users", "/api/admin", "/api/v1/users", "/api/v1/admin",
    "/api/v2/users", "/api/v2/admin", "/api/internal", "/api/debug",
    "/swagger-ui.html", "/swagger-ui", "/v3/api-docs", "/api-docs",
    "/graphql", "/graphiql", "/playground",
    "/debug", "/trace", "/config", "/env",
    "/health", "/metrics", "/info",
    "/__admin", "/_debug", "/_internal",
]


def origin(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _similarity(a, b):
    return SequenceMatcher(None, a or "", b or "").ratio()


def _extract_id_params(url):
    """Return dict of {param: value} for numeric/UUID-like parameters."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    id_params = {}
    uuid_re = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)

    for k, v in params.items():
        if not v:
            continue
        val = v[0]
        if val.isdigit() or uuid_re.match(val):
            id_params[k] = val

    # Also detect numeric path segments: /users/42, /items/uuid
    path = parsed.path
    segments = path.strip("/").split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit() and int(seg) > 0:
            id_params[f"__path_seg_{i}"] = seg

    return id_params


def _mutate_id(value):
    """Generate nearby IDs to fuzz for IDOR."""
    uuid_re = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    if uuid_re.match(value):
        # Replace last segment with zeros and ones to probe other resources
        return [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            value[:-1] + ("f" if value[-1] != "f" else "e"),
        ]
    if value.isdigit():
        n = int(value)
        candidates = set()
        for delta in range(-3, 4):
            candidate = n + delta
            if candidate > 0 and str(candidate) != value:
                candidates.add(str(candidate))
        candidates.update(["1", "2", "999999", "0"])
        return sorted(candidates)
    return []


def _test_idor_param(client, url, param, original_value, original_response):
    """Try mutated IDs on a query parameter. Returns list of result dicts."""
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for mutated_val in _mutate_id(original_value):
        mut = params.copy()
        mut[param] = mutated_val
        test_url = urlunparse(parsed._replace(query=urlencode(mut, doseq=True)))
        try:
            r = client.get(test_url)
            if r.status_code != 200:
                continue
            body = r.text or ""
            orig_body = original_response.text or ""

            if len(body) < 80:
                continue

            sim = _similarity(body, orig_body)
            content_diff = abs(len(body) - len(orig_body))

            # Different content of similar size = likely different resource (IDOR candidate)
            if 0.30 < sim < 0.92 and content_diff > 100:
                results.append({
                    "control": f"IDOR posible: {param}={mutated_val}",
                    "status": "Posible hallazgo",
                    "severity": "Alta",
                    "description": (
                        f"Modificar {param} de '{original_value}' a '{mutated_val}' devuelve "
                        f"contenido distinto al original. Posible acceso a recurso ajeno."
                    ),
                    "evidence": (
                        f"URL: {test_url} | Status: {r.status_code} | "
                        f"Similitud con original: {sim:.2f} | Diferencia bytes: {content_diff}"
                    ),
                    "recommendation": (
                        "Implementar autorización server-side por objeto. Verificar que el "
                        "recurso pertenece al usuario en sesión antes de devolver los datos."
                    ),
                })
                break
        except Exception:
            logger.debug("Fallo en prueba IDOR por parámetro", exc_info=True)
    return results


def mutate_numeric_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    candidates = []

    for key, values in params.items():
        if not values:
            continue
        value = values[0]
        if value.isdigit():
            for replacement in ["0", "1", "2", "999999"]:
                mutated = params.copy()
                mutated[key] = replacement
                candidates.append(urlunparse(parsed._replace(query=urlencode(mutated, doseq=True))))

    return candidates


MAX_IDOR_PAGES = 30


def scan_access_control(target_url, pages, client=None):
    client = client or HttpClient()
    results = []
    base = origin(target_url)

    # 1. Sensitive endpoints
    for endpoint in SENSITIVE_ENDPOINTS:
        url = base + endpoint

        try:
            response = client.get(url)
            content_type = response.headers.get("Content-Type", "")

            if response.status_code == 200 and "text/html" not in content_type.lower():
                results.append({
                    "control": f"Endpoint sensible accesible: {endpoint}",
                    "status": "Posible hallazgo",
                    "severity": "Alta",
                    "description": "Endpoint sensible accesible con respuesta no HTML genérica.",
                    "evidence": f"URL: {url} | Status: {response.status_code} | Content-Type: {content_type} | Tamaño: {len(response.text or '')}",
                    "recommendation": "Revisar autenticación/autorización y restringir endpoints administrativos."
                })

            elif response.status_code == 200 and any(x in response.text.lower() for x in ["users", "admin", "actuator", "swagger", "openapi", "management"]):
                results.append({
                    "control": f"Endpoint sensible potencialmente expuesto: {endpoint}",
                    "status": "Posible hallazgo",
                    "severity": "Alta",
                    "description": "Endpoint sensible devuelve contenido compatible con funcionalidad interna.",
                    "evidence": f"URL: {url} | Status: {response.status_code}",
                    "recommendation": "Validar control de acceso, autenticación y exposición de documentación/API."
                })

        except Exception:
            continue

    # 2. IDOR-like numeric/UUID parameter probing
    for page in (pages or [])[:MAX_IDOR_PAGES]:
        page_url = page.get("final_url") or page.get("url") or ""
        id_params = _extract_id_params(page_url)

        if not id_params:
            continue

        try:
            original_response = client.get(page_url)
        except Exception:
            continue

        if original_response.status_code != 200:
            continue

        for param, original_value in id_params.items():
            if param.startswith("__path_seg_"):
                continue  # path segment IDOR requires URL rewriting, skip for now
            idor_results = _test_idor_param(client, page_url, param, original_value, original_response)
            results.extend(idor_results)

    if not results:
        results.append({
            "control": "Control de acceso",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron endpoints sensibles expuestos ni indicios básicos de IDOR.",
            "evidence": "Sin exposición confirmada.",
            "recommendation": "Complementar con pruebas autenticadas multi-rol."
        })

    return results