import re
from urllib.parse import urlparse

from scanner.ai_agent.schemas import AIDecision
from scanner.ai_agent.memory import load_memory


AUTH_KEYWORDS = [
    "login",
    "signin",
    "auth",
    "session",
    "iniciar-sesion",
    "inicio-sesion",
    "acceder",
    "entrar",
]

REGISTER_KEYWORDS = [
    "registro",
    "register",
    "signup",
    "crear-cuenta",
    "crear cuenta",
]

API_PATTERNS = [
    r"/api/[a-zA-Z0-9_\-/]+",
    r"/auth/[a-zA-Z0-9_\-/]+",
    r"/login",
    r"/signin",
    r"/session",
]


def safe_text(value):
    return str(value or "")


def url_contains(url, keywords):
    value = safe_text(url).lower()
    return any(keyword in value for keyword in keywords)


def detect_framework(html):
    lower = safe_text(html).lower()

    if "__next_data__" in lower or "/_next/static/" in lower:
        return "nextjs"

    if "ng-version" in lower or "angular" in lower:
        return "angular"

    if "react" in lower or "root" in lower:
        return "react"

    if "vue" in lower:
        return "vue"

    return "unknown"


def extract_candidate_endpoints(html):
    html = safe_text(html)
    endpoints = set()

    for pattern in API_PATTERNS:
        for match in re.findall(pattern, html):
            endpoints.add(match)

    return sorted(endpoints)


def infer_page_type(page):
    url = safe_text(page.get("url"))
    final_url = safe_text(page.get("final_url"))
    classification = safe_text(page.get("classification")).lower()
    html = safe_text(page.get("html"))

    if classification in ["auth", "registration", "admin_candidate", "api_candidate"]:
        return classification

    if url_contains(url, AUTH_KEYWORDS) or url_contains(final_url, AUTH_KEYWORDS):
        return "auth"

    if url_contains(url, REGISTER_KEYWORDS) or url_contains(final_url, REGISTER_KEYWORDS):
        return "registration"

    if "/api" in url.lower() or "/api" in final_url.lower():
        return "api_candidate"

    if any(x in url.lower() for x in ["admin", "dashboard", "panel", "backoffice"]):
        return "admin_candidate"

    if "__next_data__" in html.lower():
        return "spa_page"

    return "unknown"


def analyze_page(page):
    memory = load_memory()

    url = safe_text(page.get("final_url") or page.get("url"))
    html = safe_text(page.get("html"))
    page_type = infer_page_type(page)
    framework = detect_framework(html)
    endpoints = extract_candidate_endpoints(html)

    decision = AIDecision(
        page_type=page_type,
        confidence=0.45,
        metadata={
            "url": url,
            "framework": framework,
            "memory_patterns": len(memory.get("patterns", [])),
        },
    )

    if page_type == "auth":
        decision.confidence = 0.9
        decision.requires_browser_dom = True
        decision.requires_api_endpoint_discovery = True
        decision.should_test_auth_sqli = True
        decision.reason = (
            "Ruta de autenticación detectada. Debe analizarse DOM renderizado y tráfico de red "
            "para identificar el endpoint real de login."
        )
        decision.recommended_next_steps = [
            "render_dom_with_playwright",
            "extract_login_selectors",
            "capture_network_on_submit",
            "identify_auth_api_endpoint",
            "run_auth_payloads_against_browser_or_api",
        ]
        decision.selectors = {
            "username_candidates": "input[type='email'], input[type='text'], input[name*='email' i], input[placeholder*='correo' i]",
            "password_candidates": "input[type='password'], input[name*='pass' i], input[placeholder*='contraseña' i]",
            "submit_candidates": "button[type='submit'], button, input[type='submit']",
        }

    elif page_type == "registration":
        decision.confidence = 0.85
        decision.requires_browser_dom = True
        decision.requires_api_endpoint_discovery = True
        decision.reason = "Ruta de registro detectada. Debe analizarse DOM renderizado y endpoints API."
        decision.recommended_next_steps = [
            "render_dom_with_playwright",
            "extract_registration_selectors",
            "capture_network_on_submit",
            "validate_registration_controls",
        ]

    elif framework in ["nextjs", "react", "angular", "vue"]:
        decision.confidence = 0.7
        decision.requires_browser_dom = True
        decision.requires_api_endpoint_discovery = True
        decision.reason = (
            f"Framework cliente detectado: {framework}. El HTML estático puede no contener formularios reales."
        )
        decision.recommended_next_steps = [
            "render_dom_with_playwright",
            "extract_runtime_dom",
            "capture_network_requests",
        ]

    if endpoints:
        decision.candidate_endpoints = endpoints
        decision.requires_api_endpoint_discovery = True

    return decision.to_dict()


def enrich_pages_with_ai_context(pages):
    enriched = []

    for page in pages or []:
        copy = dict(page)
        copy["ai_context"] = analyze_page(copy)
        enriched.append(copy)

    return enriched