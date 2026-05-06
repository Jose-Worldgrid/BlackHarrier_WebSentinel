from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs
import re

from bs4 import BeautifulSoup

from scanner.http_client import HttpClient


BINARY_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".mp4", ".mp3", ".avi", ".mov", ".woff", ".woff2", ".ttf",
    ".eot"
)

INTERESTING_RESOURCE_EXTENSIONS = (
    ".css", ".js", ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz",
    ".csv", ".xml", ".json", ".map", ".txt", ".log", ".bak",
    ".backup", ".sql", ".env", ".config", ".yml", ".yaml"
)

COMMON_ENTRY_PATHS = (
    "/",
    "/es",
    "/login",
    "/es/login",
    "/register",
    "/es/register",
    "/signup",
    "/signin",
    "/admin",
    "/dashboard",
    "/account",
    "/profile",
    "/api",
    "/api/v1",
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
    "/.well-known/security.txt",
)


def normalize_url(url: str) -> str:
    clean, _ = urldefrag(str(url or "").strip())
    return clean.rstrip("/")


def get_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def same_domain(base_url: str, candidate_url: str) -> bool:
    return urlparse(base_url).netloc == urlparse(candidate_url).netloc


def has_binary_extension(url: str) -> bool:
    return urlparse(url).path.lower().endswith(BINARY_EXTENSIONS)


def has_interesting_resource_extension(url: str) -> bool:
    return urlparse(url).path.lower().endswith(INTERESTING_RESOURCE_EXTENSIONS)


def is_valid_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def is_crawlable_url(url: str) -> bool:
    if not is_valid_http_url(url):
        return False

    if has_binary_extension(url):
        return False

    return True


def looks_like_html(response) -> bool:
    content_type = response.headers.get("Content-Type", "").lower()
    body = response.text or ""
    body_lower = body[:5000].lower()

    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        return True

    return any(marker in body_lower for marker in (
        "<html",
        "<!doctype html",
        "<head",
        "<body",
        "<form",
        "<a ",
        "<script",
        "__next_data__",
        "vite",
        "react",
        "vue",
        "svelte",
    ))


def extract_links(current_url: str, html: str) -> set[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    links = set()

    for tag in soup.find_all(["a", "link"], href=True):
        links.add(urljoin(current_url, tag["href"]))

    for tag in soup.find_all(["script", "img", "source", "iframe"], src=True):
        links.add(urljoin(current_url, tag["src"]))

    for tag in soup.find_all("form"):
        action = tag.get("action")
        if action:
            links.add(urljoin(current_url, action))
        else:
            links.add(current_url)

    for tag in soup.find_all(attrs={"data-href": True}):
        links.add(urljoin(current_url, tag["data-href"]))

    for tag in soup.find_all(attrs={"data-url": True}):
        links.add(urljoin(current_url, tag["data-url"]))

    # Extrae rutas embebidas en JS/HTML: "/login", "/api/...", etc.
    route_candidates = re.findall(
        r"""["'`](\/[a-zA-Z0-9_\-\/.?=&%#]+)["'`]""",
        html or ""
    )

    for route in route_candidates:
        if route.startswith("//"):
            continue
        links.add(urljoin(current_url, route))

    return links


def extract_forms(current_url: str, html: str) -> list[dict]:
    soup = BeautifulSoup(html or "", "html.parser")
    forms = []

    for form in soup.find_all("form"):
        fields = []

        for field in form.find_all(["input", "textarea", "select"]):
            fields.append({
                "name": field.get("name", ""),
                "type": field.get("type", field.name),
                "id": field.get("id", ""),
                "placeholder": field.get("placeholder", "")
            })

        forms.append({
            "action": urljoin(current_url, form.get("action") or current_url),
            "method": (form.get("method") or "GET").upper(),
            "fields": fields
        })

    return forms


def classify_url(url: str) -> str:
    path = urlparse(url).path.lower()
    query = parse_qs(urlparse(url).query)

    if path.endswith(INTERESTING_RESOURCE_EXTENSIONS):
        return "resource"

    if any(x in path for x in ("login", "signin", "auth")):
        return "auth"

    if any(x in path for x in ("register", "signup")):
        return "registration"

    if any(x in path for x in ("admin", "dashboard", "panel")):
        return "admin"

    if path.startswith("/api") or "/api/" in path:
        return "api"

    if query:
        return "parameterized"

    return "html_candidate"


def seed_common_paths(base_url: str) -> deque:
    origin = get_origin(base_url)
    queued = deque([base_url])

    for path in COMMON_ENTRY_PATHS:
        queued.append(normalize_url(urljoin(origin, path)))

    return queued


def crawl_site(base_url: str, max_pages: int | None = None, client=None, hard_limit: int = 5000):
    client = client or HttpClient(verify_ssl=False)

    base_url = normalize_url(client.normalize_url(base_url))
    origin = get_origin(base_url)

    visited = set()
    queued = seed_common_paths(base_url)
    pages = []
    discovered_resources = set()

    while queued:
        if max_pages is not None and len(pages) >= max_pages:
            break

        if len(visited) >= hard_limit:
            print(f"[CRAWLER SAFETY STOP] hard_limit alcanzado: {hard_limit}")
            break

        current = normalize_url(queued.popleft())

        if current in visited:
            continue

        if not same_domain(origin, current):
            continue

        if not is_crawlable_url(current):
            continue

        visited.add(current)

        try:
            response = client.get(current)
        except Exception as exc:
            print(f"[CRAWLER ERROR] {current} -> {type(exc).__name__}: {exc}")
            continue

        html_text = response.text or ""
        content_type = response.headers.get("Content-Type", "")

        print(
            "[CRAWLER RESPONSE]",
            current,
            response.status_code,
            content_type,
            "len=",
            len(html_text)
        )

        final_url = normalize_url(response.url or current)

        if final_url not in visited and same_domain(origin, final_url):
            visited.add(final_url)

        if has_interesting_resource_extension(final_url):
            discovered_resources.add(final_url)
            continue

        if not html_text.strip():
            continue

        if not looks_like_html(response):
            continue

        forms = extract_forms(final_url, html_text)

        page = {
            "url": current,
            "final_url": final_url,
            "status_code": response.status_code,
            "content_type": content_type,
            "html": html_text,
            "forms": forms,
            "classification": classify_url(final_url)
        }

        pages.append(page)

        extracted_links = extract_links(final_url, html_text)

        print(
            "[CRAWLER LINKS]",
            final_url,
            "links=",
            len(extracted_links),
            "forms=",
            len(forms)
        )

        for absolute in extracted_links:
            absolute = normalize_url(absolute)

            if not is_valid_http_url(absolute):
                continue

            if not same_domain(origin, absolute):
                continue

            if has_binary_extension(absolute):
                continue

            if has_interesting_resource_extension(absolute):
                discovered_resources.add(absolute)
                continue

            if absolute not in visited and absolute not in queued:
                queued.append(absolute)

    print("[CRAWLER FINAL PAGES]", len(pages))
    for page in pages[:20]:
        print(
            "[PAGE]",
            page.get("status_code"),
            page.get("classification"),
            page.get("url"),
            "forms=",
            len(page.get("forms", []))
        )

    if discovered_resources:
        print("[CRAWLER RESOURCES]", len(discovered_resources))
        for resource in list(sorted(discovered_resources))[:20]:
            print("[RESOURCE]", resource)

    return pages