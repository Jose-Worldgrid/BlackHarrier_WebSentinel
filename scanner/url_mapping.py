from urllib.parse import urljoin, urlparse
import logging
from bs4 import BeautifulSoup
from scanner.http_client import HttpClient
import xml.etree.ElementTree as ET


logger = logging.getLogger(__name__)


COMMON_PATHS = [
    "/", "/login", "/admin", "/dashboard", "/api", "/api/v1",
    "/swagger-ui.html", "/v3/api-docs", "/actuator", "/actuator/health",
    "/robots.txt", "/sitemap.xml"
]


def same_host(base, candidate):
    return urlparse(base).netloc == urlparse(candidate).netloc


def discover_from_robots(client, base_url):
    urls = []
    robots_url = urljoin(base_url, "/robots.txt")

    try:
        response = client.get(robots_url)

        if response.status_code == 200:
            for line in response.text.splitlines():
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    value = line.split(":", 1)[1].strip()
                    if value:
                        urls.append(urljoin(base_url, value))
    except Exception:
        logger.debug("Fallo leyendo robots.txt", exc_info=True)

    return urls


def discover_from_sitemap(client, base_url):
    urls = []
    sitemap_url = urljoin(base_url, "/sitemap.xml")

    try:
        response = client.get(sitemap_url)

        if response.status_code != 200:
            return urls

        root = ET.fromstring(response.text)

        for elem in root.iter():
            if elem.tag.endswith("loc") and elem.text:
                urls.append(elem.text.strip())

    except Exception:
        logger.debug("Fallo leyendo sitemap.xml", exc_info=True)

    return urls


MAX_DISCOVERED_URLS = 200
MAX_CHECKED_URLS    = 150


def map_urls(base_url: str, pages, client=None):
    client = client or HttpClient()
    discovered = set()

    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

    for path in COMMON_PATHS:
        discovered.add(urljoin(origin, path))

    for u in discover_from_robots(client, origin):
        if len(discovered) >= MAX_DISCOVERED_URLS:
            break
        discovered.add(u)

    for u in discover_from_sitemap(client, origin):
        if len(discovered) >= MAX_DISCOVERED_URLS:
            break
        discovered.add(u)

    for page in pages:
        if len(discovered) >= MAX_DISCOVERED_URLS:
            break

        html_content = page.get("html") or ""
        page_url = page.get("url") or page.get("final_url") or ""
        if not page_url:
            continue

        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception:
            continue

        for tag in soup.find_all(["a", "link"], href=True):
            if len(discovered) >= MAX_DISCOVERED_URLS:
                break
            href = tag.get("href", "")
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                discovered.add(urljoin(page_url, href))

        for tag in soup.find_all("script", src=True):
            if len(discovered) >= MAX_DISCOVERED_URLS:
                break
            src = tag.get("src", "")
            if src:
                discovered.add(urljoin(page_url, src))

    same_host_urls = sorted(u for u in discovered if same_host(origin, u))
    checked = []

    for url in same_host_urls[:MAX_CHECKED_URLS]:
        try:
            response = client.get(url)
            checked.append({
                "url": url,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "size": len(response.text or "")
            })
        except Exception:
            checked.append({
                "url": url,
                "status": "error",
                "content_type": "",
                "size": 0
            })

    return [{
        "control": "Mapa de URLs",
        "status": "Detectado",
        "severity": "Informativa",
        "description": f"URLs asociadas descubiertas: {len(discovered)} (comprobadas: {len(checked)}, límite: {MAX_CHECKED_URLS}).",
        "evidence": " | ".join([f"{x['status']} {x['url']}" for x in checked[:30]]),
        "recommendation": "Analizar manualmente rutas sensibles, endpoints autenticados y APIs detectadas."
    }]