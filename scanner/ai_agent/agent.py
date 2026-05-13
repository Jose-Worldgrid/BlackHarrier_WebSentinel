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


ATTACK_TEMPLATES = {
    "auth": ["SQL Injection Auth (Browser)", "Control de acceso", "CSRF", "JWT"],
    "registration": ["SQL Injection", "CSRF", "XSS reflejado", "Control de acceso"],
    "admin_candidate": ["Control de acceso", "SQL Injection", "Path Traversal", "XSS reflejado"],
    "api_candidate": ["API Discovery", "SQL Injection", "JWT", "Control de acceso"],
    "spa_page": ["XSS DOM", "XSS reflejado", "SSRF", "Path Traversal"],
    "unknown": ["SQL Injection", "XSS reflejado", "Open Redirect", "SSRF"],
}

FRAMEWORK_ATTACK_BONUS = {
    "nextjs": ["XSS DOM", "API Discovery"],
    "react": ["XSS DOM", "API Discovery"],
    "angular": ["XSS DOM", "API Discovery"],
    "vue": ["XSS DOM", "API Discovery"],
}


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


def _domain(url):
    return urlparse(safe_text(url)).netloc.lower()


def selector_hints_from_memory(memory, url):
    host = _domain(url)
    hints = {}

    for item in memory.get("successful_selectors", [])[-200:]:
        selector_url = safe_text(item.get("url"))
        if host and _domain(selector_url) != host:
            continue
        selector_type = safe_text(item.get("selector_type"))
        selector = safe_text(item.get("selector"))
        if selector_type and selector:
            hints[selector_type] = selector

    return hints


def endpoint_hints_from_memory(memory, url):
    host = _domain(url)
    endpoints = []

    for item in memory.get("endpoint_patterns", [])[-300:]:
        if host and safe_text(item.get("host")) != host:
            continue
        endpoint = safe_text(item.get("endpoint"))
        if endpoint:
            endpoints.append(endpoint)

    seen = set()
    unique = []
    for endpoint in endpoints:
        if endpoint not in seen:
            seen.add(endpoint)
            unique.append(endpoint)
    return unique[:20]


def _module_success_rate(memory, module_name):
    stats = memory.get("attack_stats", {}).get(module_name, {})
    attempts = int(stats.get("attempts", 0))
    findings = int(stats.get("findings", 0))
    if attempts <= 0:
        return 0.0
    return findings / attempts


def build_recommended_attacks(memory, page_type, framework):
    base = list(ATTACK_TEMPLATES.get(page_type, ATTACK_TEMPLATES["unknown"]))
    for attack in FRAMEWORK_ATTACK_BONUS.get(framework, []):
        if attack not in base:
            base.append(attack)

    scored = []
    for index, attack in enumerate(base):
        score = _module_success_rate(memory, attack)
        # Preserve deterministic order as soft tie-breaker.
        score += max(0, 0.05 - (index * 0.002))
        scored.append((attack, score))

    scored.sort(key=lambda item: item[1], reverse=True)

    recommendations = []
    for attack, score in scored[:6]:
        if score >= 0.35:
            priority = "high"
        elif score >= 0.12:
            priority = "medium"
        else:
            priority = "low"
        recommendations.append({
            "name": attack,
            "priority": priority,
            "confidence": round(score, 3),
            "reason": "Priorizado segun efectividad historica del agente para este tipo de objetivo.",
        })

    return recommendations


def confidence_from_memory(memory, page_type, base_confidence):
    stats = memory.get("page_type_stats", {}).get(page_type, {})
    seen = int(stats.get("seen", 0))
    findings = int(stats.get("audits_with_findings", 0))

    if seen <= 0:
        return base_confidence

    ratio = findings / max(seen, 1)
    adjustment = min(0.12, ratio * 0.12)
    return min(0.98, base_confidence + adjustment)


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

    memory_endpoint_hints = endpoint_hints_from_memory(memory, url)
    if memory_endpoint_hints:
        merged = list(dict.fromkeys(decision.candidate_endpoints + memory_endpoint_hints))
        decision.candidate_endpoints = merged[:30]

    selector_hints = selector_hints_from_memory(memory, url)
    if selector_hints:
        merged_selectors = dict(decision.selectors or {})
        merged_selectors.update(selector_hints)
        decision.selectors = merged_selectors

    decision.recommended_attacks = build_recommended_attacks(memory, page_type, framework)
    decision.confidence = confidence_from_memory(memory, page_type, decision.confidence)
    decision.metadata["history_candidates"] = len(memory_endpoint_hints)
    decision.metadata["recommended_attacks_count"] = len(decision.recommended_attacks)

    return decision.to_dict()


def enrich_pages_with_ai_context(pages):
    enriched = []

    for page in pages or []:
        copy = dict(page)
        copy["ai_context"] = analyze_page(copy)
        enriched.append(copy)

    return enriched