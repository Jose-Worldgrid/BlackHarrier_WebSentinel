import json
import os
import re
import subprocess
from urllib.parse import urljoin, urlparse, urldefrag

from scanner.tool_detection import resolve_binary


URL_RE = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)
REL_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./?=&%#:+@~]+$")

INTERESTING_FILE_SUFFIXES = (
    ".js", ".json", ".txt", ".xml", ".php", ".aspx", ".jsp", ".cgi",
    ".map", ".yaml", ".yml", ".env", ".conf", ".config", ".bak", ".sql",
)


def _startupinfo_hidden():
    if os.name != "nt":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0
    return info


def _resolve_katana_binary():
    resolved, _ = resolve_binary(
        "katana",
        explicit_candidates=[
            r"C:\tools\katana\katana.exe",
            r"C:\Program Files\katana\katana.exe",
        ],
    )
    return resolved


def _looks_like_js_noise(line: str) -> bool:
    text = str(line or "").strip()
    if not text:
        return True

    # Ignore huge inline JS chunks frequently printed by tooling or responses.
    if len(text) > 800 and ("function " in text or "=>" in text or "{\"" in text):
        return True

    markers = [
        "function ui(", "webpack", "__next", "react", "use strict", "return ",
        "var ", "const ", "let ", "(()=>", "export ", "import ",
    ]
    if len(text) > 220 and sum(1 for m in markers if m in text.lower()) >= 2:
        return True

    # Dense symbols indicate code, not URL/path output.
    symbol_ratio = sum(1 for ch in text if ch in "{}();[]") / max(len(text), 1)
    if len(text) > 180 and symbol_ratio > 0.18:
        return True

    return False


def _normalize_url(url: str) -> str:
    clean, _ = urldefrag(str(url or "").strip())
    return clean.rstrip("/")


def _same_origin(target_url: str, candidate: str) -> bool:
    base = urlparse(str(target_url or "").strip())
    cur = urlparse(str(candidate or "").strip())
    if not base.scheme or not base.hostname:
        return False
    if not cur.scheme or not cur.hostname:
        return False
    base_port = base.port or (443 if base.scheme == "https" else 80)
    cur_port = cur.port or (443 if cur.scheme == "https" else 80)
    return base.scheme == cur.scheme and base.hostname == cur.hostname and base_port == cur_port


def _classify_url(url: str) -> str:
    path = urlparse(url).path.lower()
    if any(x in path for x in ["/login", "signin", "auth", "iniciar-sesion", "inicio-sesion"]):
        return "auth"
    if any(x in path for x in ["register", "signup", "registro", "crear-cuenta"]):
        return "registration"
    if any(x in path for x in ["admin", "dashboard", "panel", "backoffice", "manager"]):
        return "admin_candidate"
    if any(x in path for x in ["/api", "/graphql", "swagger", "openapi", "api-docs"]):
        return "api_candidate"
    if path.endswith(INTERESTING_FILE_SUFFIXES):
        return "sensitive_candidate"
    return "html_candidate"


def _extract_candidates_from_line(raw_line: str, target_url: str):
    line = str(raw_line or "").strip()
    if not line or _looks_like_js_noise(line):
        return []

    candidates = []

    # 1) JSON line output from katana
    if line.startswith("{") and line.endswith("}"):
        try:
            obj = json.loads(line)
            direct = [
                obj.get("url"),
                (obj.get("request") or {}).get("endpoint"),
                obj.get("endpoint"),
                obj.get("path"),
            ]
            for item in direct:
                text = str(item or "").strip()
                if text:
                    candidates.append(text)
        except Exception:
            pass

    # 2) Full absolute URLs found in plain output line
    for match in URL_RE.findall(line):
        candidates.append(match)

    # 3) Relative endpoint line
    if REL_PATH_RE.match(line):
        candidates.append(line)

    normalized = []
    seen = set()
    for item in candidates:
        text = str(item or "").strip().strip("'\"")
        if not text:
            continue
        if text.startswith("//"):
            continue
        if text.startswith("/"):
            text = urljoin(target_url, text)

        parsed = urlparse(text)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue
        text = _normalize_url(text)
        if not _same_origin(target_url, text):
            continue

        if text in seen:
            continue
        seen.add(text)
        normalized.append(text)

    return normalized


def run_katana_discovery(target_url: str, depth: int = 3, timeout: int = 300):
    """Run Katana and return clean scope URLs/endpoints for downstream modules.

    Returns:
      {
        "available": bool,
        "executed": bool,
        "urls": list[str],
        "rows": list[dict],
        "error": str,
      }
    """
    katana_bin = _resolve_katana_binary()
    if not katana_bin:
        return {
            "available": False,
            "executed": False,
            "urls": [],
            "rows": [],
            "error": "katana_not_found",
        }

    depth_value = max(1, min(int(depth or 3), 5))
    cmd = [katana_bin, "-u", target_url, "-d", str(depth_value), "-jc", "-silent", "-nc", "-jsonl"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=int(timeout or 300),
            startupinfo=_startupinfo_hidden(),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        if proc.returncode != 0 and not stdout.strip():
            return {
                "available": True,
                "executed": False,
                "urls": [],
                "rows": [],
                "error": stderr[:240] or f"exit_code_{proc.returncode}",
            }

        urls = []
        seen = set()
        for line in stdout.splitlines():
            for candidate in _extract_candidates_from_line(line, target_url):
                if candidate in seen:
                    continue
                seen.add(candidate)
                urls.append(candidate)

        rows = [{
            "control": "Katana Discovery",
            "status": "Detectado" if urls else "No evidenciado",
            "severity": "Informativa",
            "description": "Crawling dinámico con Katana para ampliar endpoints del scope.",
            "evidence": f"Comando: {' '.join(cmd)} | Endpoints útiles: {len(urls)}",
            "recommendation": "Usar endpoints consolidados para pruebas de cabeceras, authN/authZ e inyecciones.",
        }]

        for item in urls[:30]:
            rows.append({
                "control": f"Endpoint Katana - {_classify_url(item)}",
                "status": "Detectado",
                "severity": "Informativa",
                "description": "Endpoint útil extraído por Katana tras filtrado anti-ruido JS.",
                "evidence": item,
                "recommendation": "Incluir en scope de escaneo y validar controles de seguridad por ruta.",
            })

        return {
            "available": True,
            "executed": True,
            "urls": urls,
            "rows": rows,
            "error": "",
        }

    except Exception as exc:
        return {
            "available": True,
            "executed": False,
            "urls": [],
            "rows": [{
                "control": "Katana Discovery",
                "status": "Error",
                "severity": "Media",
                "description": "Falló la ejecución de Katana durante discovery dinámico.",
                "evidence": str(exc)[:240],
                "recommendation": "Verificar PATH/permisos del binario Katana y conectividad del objetivo.",
            }],
            "error": str(exc)[:240],
        }
