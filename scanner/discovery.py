from urllib.parse import urljoin, urlparse
from difflib import SequenceMatcher

from bs4 import BeautifulSoup

from scanner.http_client import HttpClient
from scanner.wordlists.web_paths import COMMON_WEB_PATHS


LANGUAGE_PREFIXES = ["es", "en"]

REPORTABLE_DISCOVERY_CLASSES = {
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

BAD_PATHS = {
    "/&",
    "/#",
    "/?",
    "/undefined",
    "/null",
    "/none",
}


def normalize_url(url: str) -> str:
    return str(url or "").strip().rstrip("/")


def safe_status(value):
    try:
        return int(value)
    except Exception:
        return 0


def is_effective_redirect(requested_url, final_url):
    requested = normalize_url(requested_url)
    final = normalize_url(final_url)
    return bool(requested and final and requested != final)


def get_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def same_domain(origin: str, url: str) -> bool:
    return urlparse(origin).netloc == urlparse(url).netloc


def get_title(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    title = soup.find("title")
    return title.get_text(strip=True) if title else ""


def looks_like_html(response) -> bool:
    content_type = response.headers.get("Content-Type", "").lower()
    body = response.text or ""
    lower = body[:5000].lower()

    return (
        "text/html" in content_type
        or "<html" in lower
        or "<!doctype html" in lower
        or "<body" in lower
        or "__next_data__" in lower
        or "react" in lower
        or "next" in lower
    )


def detect_language_prefixes(base_url: str, pages=None):
    prefixes = set(LANGUAGE_PREFIXES)

    parsed = urlparse(base_url)
    first = parsed.path.strip("/").split("/")[0] if parsed.path.strip("/") else ""

    if first and len(first) <= 5:
        prefixes.add(first)

    for page in pages or []:
        for key in ["url", "final_url"]:
            parsed_page = urlparse(page.get(key) or "")
            first = parsed_page.path.strip("/").split("/")[0] if parsed_page.path.strip("/") else ""

            if first and len(first) <= 5:
                prefixes.add(first)

    return sorted(prefixes)


def build_candidate_urls(base_url: str, pages=None):
    parsed = urlparse(base_url)

    if parsed.path in BAD_PATHS:
        base_url = get_origin(base_url)

    origin = get_origin(base_url)
    prefixes = detect_language_prefixes(base_url, pages)

    candidates = set()

    for path in COMMON_WEB_PATHS:
        if not path.startswith("/"):
            path = f"/{path}"

        candidates.add(normalize_url(urljoin(origin, path)))

        for prefix in prefixes:
            candidates.add(normalize_url(urljoin(origin, f"/{prefix}{path}")))

    return sorted(candidates)


def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a or "", b or "").ratio()


def is_ssl_cert_error(exc: Exception) -> bool:
    text = str(exc or "").lower()
    return (
        "certificate verify failed" in text
        or "sslcertverificationerror" in text
        or "cert_verify_failed" in text
    )


def to_http_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return url.replace("https://", "http://", 1)
    return url


def get_soft404_baseline(client, origin):
    test_url = urljoin(origin, "/__blackharrier_404_probe_9f8d7a6b__")

    try:
        response = client.get(test_url)
        return {
            "status_code": response.status_code,
            "length": len(response.text or ""),
            "title": get_title(response.text or ""),
            "body": response.text or "",
        }
    except Exception:
        return None


def is_soft_404(response, baseline) -> bool:
    if response.status_code == 404:
        return True

    body = response.text or ""
    title = get_title(body).lower()

    error_markers = [
        "404",
        "not found",
        "no encontrado",
        "página no encontrada",
        "page not found",
        "ruta no encontrada",
    ]

    if any(marker in title for marker in error_markers):
        return True

    if baseline and response.status_code == 200:
        length_diff = abs(len(body) - baseline.get("length", 0))
        title_ratio = similarity(get_title(body), baseline.get("title", ""))

        if length_diff < 300 and title_ratio > 0.85:
            return True

    return False


def classify_url(requested_url, final_url, response, baseline=None):
    requested_path = urlparse(requested_url).path.lower()
    final_path = urlparse(final_url).path.lower()
    body = (response.text or "")[:12000].lower()

    if is_soft_404(response, baseline):
        return "soft_404"

    if response.status_code in [401, 403]:
        return "protected"

    if response.status_code >= 500:
        return "server_error"

    if any(x in final_path for x in ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion"]):
        if any(x in requested_path for x in ["admin", "panel", "dashboard", "private", "backoffice"]):
            return "protected_redirect_to_auth"
        return "auth"

    if any(x in final_path for x in ["registro", "register", "signup", "crear-cuenta"]):
        return "registration"

    if any(x in requested_path for x in ["admin", "administrator", "panel", "dashboard", "backoffice", "manager"]):
        return "admin_candidate"

    if "/api" in requested_path or "/graphql" in requested_path or "/swagger" in requested_path or "/openapi" in requested_path:
        return "api_candidate"

    if any(x in requested_path for x in [".env", ".git", "backup", "dump", "database", "config", "settings", ".sql", ".zip"]):
        return "sensitive_candidate"

    if any(x in body for x in ["exception", "traceback", "stack trace", "sql syntax", "debug", "database error"]):
        return "error_disclosure_candidate"

    return "html_candidate"


def response_observation(classification, requested_url, final_url, response):
    if classification == "protected_redirect_to_auth":
        return "Ruta sensible que redirige a autenticación. Revisar control de acceso tras login."

    if classification == "auth":
        return "Endpoint de autenticación detectado. Prioritario para pruebas autenticadas y análisis de JS/API."

    if classification == "registration":
        return "Endpoint de registro detectado. Revisar validación, abuso de alta y enumeración."

    if classification == "protected":
        return "Ruta protegida por HTTP 401/403. Revisar autorización y exposición."

    if classification == "admin_candidate":
        return "Ruta administrativa candidata. Verificar autorización y exposición."

    if classification == "api_candidate":
        return "Endpoint API candidato. Revisar métodos, autenticación y errores."

    if classification == "sensitive_candidate":
        return "Ruta sensible candidata. Verificar exposición de secretos, backups o configuración."

    if classification == "server_error":
        return "Error 5xx detectado. Revisar posible filtrado de información."

    if classification == "error_disclosure_candidate":
        return "Respuesta con indicadores de error técnico. Revisar exposición de trazas o detalles internos."

    if classification == "soft_404":
        return "Respuesta compatible con 404 o soft-404."

    if requested_url != final_url:
        return f"Redirección detectada hacia {final_url}"

    return "Página HTML candidata."


def is_reportable_discovery_item(item):
    status_code = safe_status(item.get("status_code"))
    classification = item.get("classification", "")

    if status_code == 404:
        return False

    if classification in ["soft_404", "request_error", "html_candidate"]:
        return False

    if classification in REPORTABLE_DISCOVERY_CLASSES:
        return True

    if status_code >= 500:
        return True

    return False


def build_discovery_results(discovered):
    results = []

    interesting = [
        item for item in discovered
        if is_reportable_discovery_item(item)
    ]

    results.append({
        "control": "Discovery de superficie web",
        "status": "Detectado",
        "severity": "Informativa",
        "description": "Se ejecutó descubrimiento pasivo y activo mediante crawling y diccionario de rutas comunes.",
        "evidence": f"URLs procesadas: {len(discovered)} | Rutas relevantes: {len(interesting)}",
        "recommendation": "Revisar manualmente rutas sensibles, autenticación, registro, API y paneles administrativos."
    })

    for item in interesting[:60]:
        classification = item.get("classification", "")
        severity = "Informativa"

        if classification in ["sensitive_candidate", "server_error", "error_disclosure_candidate"]:
            severity = "Alta"
        elif classification in ["protected", "protected_redirect_to_auth", "admin_candidate", "api_candidate", "auth", "registration"]:
            severity = "Media"

        results.append({
            "control": f"Ruta descubierta - {classification}",
            "status": "Detectado",
            "severity": severity,
            "description": item.get("observation", ""),
            "evidence": (
                f"Solicitada: {item.get('requested_url')} | "
                f"Final: {item.get('final_url')} | "
                f"HTTP: {item.get('status_code')} | "
                f"Título: {item.get('title')} | "
                f"Origen: {item.get('source')}"
            ),
            "recommendation": "Incluir esta ruta en validación manual, pruebas autenticadas y análisis de control de acceso."
        })

    return results


def discover_surface(base_url: str, client=None, seed_pages=None, max_active_checks=300):
    client = client or HttpClient(verify_ssl=False)

    base_url = normalize_url(client.normalize_url(base_url))
    origin = get_origin(base_url)

    seed_pages = seed_pages or []
    candidate_urls = build_candidate_urls(base_url, seed_pages)[:max_active_checks]
    baseline = get_soft404_baseline(client, origin)

    discovered = []
    pages_by_final_url = {}
    ssl_fallback_applied = False
    request_error_count = 0
    ssl_error_count = 0

    for page in seed_pages:
        final_url = normalize_url(page.get("final_url") or page.get("url"))
        requested_url = normalize_url(page.get("url"))

        if not final_url:
            continue

        status_code = safe_status(page.get("status_code"))
        
        # Reclasificación: usar lógica completa que detecta redirecciones
        # Crear un objeto response simulado con propiedades necesarias
        class FakeResponse:
            def __init__(self, status, headers_dict):
                self.status_code = status
                self.headers = headers_dict
                self.text = page.get("html", "")
        
        fake_response = FakeResponse(status_code, {"Content-Type": page.get("content_type", "")})
        
        # Si hay redirección efectiva, detect protected_redirect_to_auth
        if is_effective_redirect(requested_url, final_url):
            if any(x in final_url.lower() for x in ["login", "signin", "auth", "iniciar-sesion", "inicio-sesion"]):
                if any(x in requested_url.lower() for x in ["admin", "panel", "dashboard", "private", "backoffice"]):
                    classification = "protected_redirect_to_auth"
                else:
                    classification = "auth"
            else:
                classification = classify_url(requested_url, final_url, fake_response, baseline)
        else:
            classification = classify_url(requested_url, final_url, fake_response, baseline)

        discovered_item = {
            "source": "crawler",
            "requested_url": page.get("url"),
            "final_url": final_url,
            "status_code": page.get("status_code"),
            "content_type": page.get("content_type", ""),
            "length": len(page.get("html", "") or ""),
            "classification": classification,
            "title": get_title(page.get("html", "")),
            "observation": "URL descubierta por crawling HTML."
        }

        discovered.append(discovered_item)

        if (
            status_code < 400
            and classification not in ["soft_404", "request_error"]
            and not is_effective_redirect(requested_url, final_url)
        ):
            pages_by_final_url[final_url] = page

    for url in candidate_urls:
        if not same_domain(origin, url):
            continue

        parsed_url = urlparse(url)
        if parsed_url.path in BAD_PATHS:
            continue

        try:
            response = client.get(url)
        except Exception as exc:
            request_error_count += 1
            if is_ssl_cert_error(exc):
                ssl_error_count += 1

            if (
                not ssl_fallback_applied
                and bool(getattr(client, "verify_ssl", True))
                and is_ssl_cert_error(exc)
            ):
                ssl_fallback_applied = True
                client.verify_ssl = False
                try:
                    response = client.get(url)
                except Exception as retry_exc:
                    # Optional fallback: try plain HTTP if HTTPS certificate chain is broken.
                    fallback_url = to_http_url(url)
                    if fallback_url != url:
                        try:
                            response = client.get(fallback_url)
                            url = fallback_url
                        except Exception:
                            discovered.append({
                                "source": "wordlist",
                                "requested_url": url,
                                "final_url": url,
                                "status_code": "error",
                                "content_type": "",
                                "length": 0,
                                "classification": "request_error",
                                "title": "",
                                "observation": f"SSL fallback retry failed: {retry_exc}"
                            })
                            continue
                    else:
                        discovered.append({
                            "source": "wordlist",
                            "requested_url": url,
                            "final_url": url,
                            "status_code": "error",
                            "content_type": "",
                            "length": 0,
                            "classification": "request_error",
                            "title": "",
                            "observation": f"SSL fallback retry failed: {retry_exc}"
                        })
                        continue
            else:
                discovered.append({
                    "source": "wordlist",
                    "requested_url": url,
                    "final_url": url,
                    "status_code": "error",
                    "content_type": "",
                    "length": 0,
                    "classification": "request_error",
                    "title": "",
                    "observation": str(exc)
                })

                if request_error_count >= 30:
                    ratio = ssl_error_count / max(request_error_count, 1)
                    if ratio >= 0.8:
                        discovered.append({
                            "source": "wordlist",
                            "requested_url": base_url,
                            "final_url": base_url,
                            "status_code": "error",
                            "content_type": "",
                            "length": 0,
                            "classification": "request_error",
                            "title": "",
                            "observation": (
                                "Discovery detenido anticipadamente: alta tasa de errores SSL/certificado. "
                                "Revisar certificado del objetivo o desactivar verificación SSL para esta auditoría."
                            )
                        })
                        break

                continue

        final_url = normalize_url(response.url or url)
        html = response.text or ""
        classification = classify_url(url, final_url, response, baseline)

        discovered_item = {
            "source": "wordlist",
            "requested_url": url,
            "final_url": final_url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "length": len(html),
            "classification": classification,
            "title": get_title(html),
            "observation": response_observation(classification, url, final_url, response)
        }

        discovered.append(discovered_item)

        if (
            response.status_code < 400
            and looks_like_html(response)
            and classification not in ["soft_404", "request_error", "html_candidate"]
            and final_url not in pages_by_final_url
        ):
            pages_by_final_url[final_url] = {
                "url": url,
                "final_url": final_url,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "html": html,
                "forms": [],
                "classification": classification
            }

    reportable_items = [
        x for x in discovered
        if is_reportable_discovery_item(x)
    ]

    results = build_discovery_results(discovered)

    return {
        "pages": list(pages_by_final_url.values()),
        "discovered": discovered,
        "results": results,
        "metrics": {
            "total_discovered": len(discovered),
            "reportable_discovered": len(reportable_items),
            "html_pages": len(pages_by_final_url),
            "request_errors": len([x for x in discovered if x.get("classification") == "request_error"]),
            "auth_routes": len([x for x in reportable_items if x.get("classification") == "auth"]),
            "registration_routes": len([x for x in reportable_items if x.get("classification") == "registration"]),
            "protected_routes": len([x for x in reportable_items if "protected" in str(x.get("classification", ""))]),
            "api_candidates": len([x for x in reportable_items if x.get("classification") == "api_candidate"]),
            "sensitive_candidates": len([x for x in reportable_items if x.get("classification") == "sensitive_candidate"]),
            "server_errors": len([x for x in reportable_items if x.get("classification") == "server_error"]),
            "soft_404": len([x for x in discovered if x.get("classification") == "soft_404"]),
        }
    }