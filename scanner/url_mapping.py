from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from scanner.http_client import HttpClient
import xml.etree.ElementTree as ET


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
        pass

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
        pass

    return urls


def map_urls(base_url: str, pages, client=None):
    client = client or HttpClient()
    discovered = set()

    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"

    for path in COMMON_PATHS:
        discovered.add(urljoin(origin, path))

    for u in discover_from_robots(client, origin):
        discovered.add(u)

    for u in discover_from_sitemap(client, origin):
        discovered.add(u)

    for page in pages:
        soup = BeautifulSoup(page["html"], "html.parser")

        for tag in soup.find_all(["a", "link"], href=True):
            discovered.add(urljoin(page["url"], tag["href"]))

        for tag in soup.find_all("script", src=True):
            discovered.add(urljoin(page["url"], tag["src"]))

    checked = []

    for url in sorted(discovered):
        if not same_host(origin, url):
            continue

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
        "description": "URLs asociadas descubiertas y comprobadas.",
        "evidence": " | ".join([f"{x['status']} {x['url']}" for x in checked[:30]]),
        "recommendation": "Analizar manualmente rutas sensibles, endpoints autenticados y APIs detectadas."
    }]