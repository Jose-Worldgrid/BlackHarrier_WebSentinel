# Modulo de escaneo y analisis para external tools pipeline.

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
import requests

from scanner.wordlists.web_paths import COMMON_WEB_PATHS
from scanner.katana_discovery import run_katana_discovery
from scanner.tool_detection import resolve_binary


HTTPX_LINE_RE = re.compile(r"^(https?://\S+)\s+(\[.+\])$")
HTTPX_BRACKETS_RE = re.compile(r"\[([^\]]*)\]")
URL_RE = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)
CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

ACTIVE_HTTPX_STATUSES = {200, 201, 202, 204, 401, 403, 405, 429}
REDIRECT_HTTPX_STATUSES = {301, 302, 303, 307, 308}
FUZZ_INTERESTING_STATUSES = {200, 301, 302, 307, 308, 403}
HIGH_IMPACT_NUCLEI_SEVERITIES = {"medium", "high", "critical"}
CIRCL_CVE_ENDPOINT = "https://cve.circl.lu/api/cve"


def _severity_es(value: str) -> str:
    sev = str(value or "").strip().lower()
    if sev in {"critical", "critica", "crítica"}:
        return "Crítica"
    if sev in {"high", "alta"}:
        return "Alta"
    if sev in {"medium", "media"}:
        return "Media"
    if sev in {"low", "baja"}:
        return "Baja"
    return "Informativa"


def _normalize_nuclei_severity(value: str) -> str:
    sev = str(value or "").strip().lower()
    if sev in {"critical", "critica", "crítica"}:
        return "critical"
    if sev in {"high", "alta"}:
        return "high"
    if sev in {"medium", "media"}:
        return "medium"
    if sev in {"low", "baja"}:
        return "low"
    return "info"


def _extract_cve_ids_from_nuclei_row(row: dict) -> list:
    info = row.get("info") if isinstance(row, dict) else {}
    info = info if isinstance(info, dict) else {}
    classification = info.get("classification") if isinstance(info, dict) else {}
    classification = classification if isinstance(classification, dict) else {}

    candidates = []

    for key in ["cve", "cve-id", "cve_id", "CVE", "CVE-ID"]:
        value = classification.get(key)
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, list):
            candidates.extend([str(x or "") for x in value])

    tags = info.get("tags")
    if isinstance(tags, list):
        candidates.extend([str(x or "") for x in tags])
    elif isinstance(tags, str):
        candidates.extend([x.strip() for x in tags.split(",") if x.strip()])

    template_id = str(row.get("template-id") or "")
    if template_id:
        candidates.append(template_id)

    text_blob = "\n".join(candidates)
    found = []
    seen = set()
    for match in CVE_ID_RE.findall(text_blob):
        cve_id = str(match or "").strip().upper()
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        found.append(cve_id)
    return found


def _fetch_circl_cve(cve_id: str, timeout: float = 8.0) -> dict:
    cve_id = str(cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return {}
    try:
        response = requests.get(f"{CIRCL_CVE_ENDPOINT}/{cve_id}", timeout=timeout)
        if response.status_code != 200:
            return {}
        payload = response.json() or {}
        if not isinstance(payload, dict):
            return {}

        references = payload.get("references") or []
        if not isinstance(references, list):
            references = []
        references = [str(x or "").strip() for x in references if str(x or "").strip().startswith("http")]

        return {
            "id": cve_id,
            "summary": str(payload.get("summary") or "").strip(),
            "cvss": payload.get("cvss"),
            "references": list(dict.fromkeys(references))[:15],
            "source": "circl",
        }
    except Exception:
        return {}


def _build_nuclei_findings(nuclei_jsonl, *, force_circl_low_info: bool = False):
    """Normalize Nuclei output and optionally enrich CVEs from CIRCL with strict relevance filtering."""
    findings = []
    circl_cache = {}
    circl_meta = {
        "enabled": True,
        "queried": 0,
        "cache_hits": 0,
        "eligible_findings": 0,
        "skipped_by_severity": 0,
        "skipped_without_cve": 0,
    }

    for row in nuclei_jsonl or []:
        raw = row if isinstance(row, dict) else {}
        info = raw.get("info") if isinstance(raw, dict) else {}
        info = info if isinstance(info, dict) else {}

        severity = _normalize_nuclei_severity(info.get("severity") or "info")
        finding = {
            "template_id": str(raw.get("template-id") or ""),
            "name": str(info.get("name") or raw.get("matcher-name") or "Nuclei finding"),
            "severity": severity,
            "matched_at": str(raw.get("matched-at") or raw.get("host") or ""),
            "raw": raw,
            "cve_ids": [],
            "circl": [],
            "circl_skipped_reason": "",
        }

        is_relevant_severity = severity in HIGH_IMPACT_NUCLEI_SEVERITIES
        if not is_relevant_severity and not force_circl_low_info:
            circl_meta["skipped_by_severity"] += 1
            finding["circl_skipped_reason"] = "severity_filtered"
            findings.append(finding)
            continue

        cve_ids = _extract_cve_ids_from_nuclei_row(raw)
        finding["cve_ids"] = cve_ids

        if not cve_ids:
            circl_meta["skipped_without_cve"] += 1
            finding["circl_skipped_reason"] = "missing_cve"
            findings.append(finding)
            continue

        circl_meta["eligible_findings"] += 1
        circl_payloads = []
        for cve_id in cve_ids:
            if cve_id in circl_cache:
                circl_meta["cache_hits"] += 1
                cached = circl_cache[cve_id]
                if cached:
                    circl_payloads.append(dict(cached))
                continue

            circl_meta["queried"] += 1
            fetched = _fetch_circl_cve(cve_id)
            circl_cache[cve_id] = fetched or {}
            if fetched:
                circl_payloads.append(dict(fetched))

        finding["circl"] = circl_payloads
        findings.append(finding)

    circl_meta["unique_cves_seen"] = len(circl_cache)
    circl_meta["resolved_cves"] = sum(1 for x in circl_cache.values() if x)
    return findings, circl_meta


def _startupinfo_hidden():
    if os.name != "nt":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0
    return info


def _resolve_binary(candidates):
    normalized = [str(item or "").strip() for item in candidates if str(item or "").strip()]
    tool_hint = ""
    for item in normalized:
        lower = item.lower()
        if lower.endswith(".exe"):
            tool_hint = os.path.splitext(os.path.basename(lower))[0]
            break
        if "\\" not in item and "/" not in item:
            tool_hint = item.replace(".exe", "")
            break

    if tool_hint:
        resolved, _ = resolve_binary(tool_hint, explicit_candidates=normalized)
        if resolved:
            return resolved

    for item in normalized:
        found = shutil.which(item)
        if found:
            return found
        if os.path.isfile(item):
            return item
    return ""


def _run_command(cmd, timeout=180):
    max_chars = max(200000, int(os.getenv("BH_PIPELINE_MAX_CAPTURE_CHARS", "1500000") or 1500000))

    def _read_limited(path):
        text = ""
        truncated = False
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(max_chars + 1)
                truncated = len(text) > max_chars
                if truncated:
                    text = text[:max_chars]
        except Exception:
            text = ""
            truncated = False
        if truncated:
            text += "\n[output-truncated]"
        return text

    out_path = ""
    err_path = ""
    try:
        out_file = tempfile.NamedTemporaryFile(prefix="bh_cmd_out_", suffix=".log", delete=False)
        err_file = tempfile.NamedTemporaryFile(prefix="bh_cmd_err_", suffix=".log", delete=False)
        out_path = out_file.name
        err_path = err_file.name
        out_file.close()
        err_file.close()

        with open(out_path, "w", encoding="utf-8", errors="replace") as stdout_fh, open(
            err_path, "w", encoding="utf-8", errors="replace"
        ) as stderr_fh:
            proc = subprocess.run(
                cmd,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                startupinfo=_startupinfo_hidden(),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                stdout=stdout_fh,
                stderr=stderr_fh,
            )

        return int(proc.returncode or 0), _read_limited(out_path), _read_limited(err_path)
    except subprocess.TimeoutExpired:
        return 124, _read_limited(out_path), "timeout_expired"
    except Exception as exc:
        return 1, "", str(exc)
    finally:
        for path in [out_path, err_path]:
            if path:
                try:
                    os.unlink(path)
                except Exception:
                    pass


def _run_command_with_input(cmd, input_text, timeout=180):
    max_chars = max(200000, int(os.getenv("BH_PIPELINE_MAX_CAPTURE_CHARS", "1500000") or 1500000))

    def _read_limited(path):
        text = ""
        truncated = False
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(max_chars + 1)
                truncated = len(text) > max_chars
                if truncated:
                    text = text[:max_chars]
        except Exception:
            text = ""
            truncated = False
        if truncated:
            text += "\n[output-truncated]"
        return text

    out_path = ""
    err_path = ""
    try:
        out_file = tempfile.NamedTemporaryFile(prefix="bh_cmd_in_out_", suffix=".log", delete=False)
        err_file = tempfile.NamedTemporaryFile(prefix="bh_cmd_in_err_", suffix=".log", delete=False)
        out_path = out_file.name
        err_path = err_file.name
        out_file.close()
        err_file.close()

        with open(out_path, "w", encoding="utf-8", errors="replace") as stdout_fh, open(
            err_path, "w", encoding="utf-8", errors="replace"
        ) as stderr_fh:
            proc = subprocess.run(
                cmd,
                input=input_text,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                startupinfo=_startupinfo_hidden(),
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                stdout=stdout_fh,
                stderr=stderr_fh,
            )

        return int(proc.returncode or 0), _read_limited(out_path), _read_limited(err_path)
    except subprocess.TimeoutExpired:
        return 124, _read_limited(out_path), "timeout_expired"
    except Exception as exc:
        return 1, "", str(exc)
    finally:
        for path in [out_path, err_path]:
            if path:
                try:
                    os.unlink(path)
                except Exception:
                    pass


def _normalize_auth_params(auth_params=None):
    auth_params = auth_params or {}
    if not isinstance(auth_params, dict):
        return {"cookie": "", "auth_header": "", "headers": []}

    cookie = str(auth_params.get("cookie") or "").strip()
    auth_header = str(auth_params.get("auth_header") or "").strip()
    headers = []

    for item in auth_params.get("headers") or []:
        text = str(item or "").strip()
        if text:
            headers.append(text)

    if auth_header:
        headers.append(auth_header)
    if cookie:
        headers.append(f"Cookie: {cookie}")


    headers = list(dict.fromkeys(headers))
    return {
        "cookie": cookie,
        "auth_header": auth_header,
        "headers": headers,
    }


def _append_auth_flags(cmd, *, auth_params=None, support_cookie_flag=False):
    normalized = _normalize_auth_params(auth_params)
    for header in normalized.get("headers") or []:
        cmd.extend(["-H", header])
    if support_cookie_flag and normalized.get("cookie"):
        cmd.extend(["-cookie", normalized["cookie"]])
    return cmd


def _normalize_sig(text: str) -> str:
    value = str(text or "").strip().lower()
    if "content-security-policy" in value or "csp" in value:
        return "missing_csp"
    if "strict-transport-security" in value or "hsts" in value:
        return "missing_hsts"
    if "x-content-type-options" in value:
        return "missing_x_content_type_options"
    if "x-frame-options" in value:
        return "missing_x_frame_options"
    if "ftp" in value and "21" in value:
        return "port_21_ftp"
    if "8080" in value:
        return "port_8080"
    if "jwt" in value:
        return "jwt_weakness"
    return value[:120]


def _internal_signatures(results):
    sigs = set()
    for row in results or []:
        blob = " ".join([
            str(row.get("Control", "") or ""),
            str(row.get("Descripción", "") or ""),
            str(row.get("Evidencia", "") or ""),
        ])
        norm = _normalize_sig(blob)
        if norm:
            sigs.add(norm)
    return sigs


def _host_from_target(target_url: str) -> str:
    parsed = urlparse(str(target_url or "").strip())
    host = parsed.hostname or str(target_url or "").strip()
    return host


def _is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except Exception:
        return False


def _run_katana(target_url: str, depth: str):
    depth_value = 3 if str(depth or "").lower() == "completo" else 2
    result = run_katana_discovery(target_url=target_url, depth=depth_value, timeout=300)
    urls = result.get("urls") or []
    status = {
        "available": bool(result.get("available")),
        "executed": bool(result.get("executed")),
        "count": len(urls),
    }
    if result.get("error"):
        status["error"] = str(result.get("error"))[:180]
    return urls, status


def _normalize_url(value: str) -> str:
    text = str(value or "").strip()
    while text.endswith("/") and len(text) > 8:
        text = text[:-1]
    return text


STATIC_ASSET_EXTENSIONS = {
    ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip", ".gz",
    ".br", ".xml", ".txt",
}


def _looks_like_static_asset(url_text: str) -> bool:
    path = (urlparse(str(url_text or "")).path or "").lower()
    return any(path.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)


def _nuclei_target_priority(url_text: str) -> tuple:
    parsed = urlparse(str(url_text or ""))
    path = parsed.path or "/"
    is_root = path in {"", "/"}
    has_ext = "." in (path.rsplit("/", 1)[-1] or "")
    depth = path.count("/")

    return (
        0 if is_root else 1,
        1 if has_ext else 0,
        depth,
        len(path),
        str(url_text),
    )


def _same_host_scope(base_url: str, candidate_url: str) -> bool:
    try:
        base = urlparse(str(base_url or "").strip())
        cur = urlparse(str(candidate_url or "").strip())
        if not base.hostname or not cur.hostname:
            return False
        return base.hostname.lower() == cur.hostname.lower()
    except Exception:
        return False


def _looks_like_js_noise(line: str) -> bool:
    text = str(line or "").strip()
    if not text:
        return True
    if text.startswith("//") or text.startswith("/*"):
        return True
    if len(text) > 240 and sum(1 for x in ["function ", "const ", "let ", "=>", "webpack", "__next"] if x in text.lower()) >= 2:
        return True
    symbol_ratio = sum(1 for ch in text if ch in "{}();[]") / max(len(text), 1)
    if len(text) > 180 and symbol_ratio > 0.20:
        return True
    return False


def _extract_katana_urls_from_line(line: str, target_url: str):
    text = str(line or "").strip()
    if not text or _looks_like_js_noise(text):
        return []

    raw = []


    if text.startswith("{") and text.endswith("}"):
        try:
            obj = json.loads(text)
            raw.extend([
                obj.get("url"),
                (obj.get("request") or {}).get("endpoint"),
                obj.get("endpoint"),
                obj.get("path"),
            ])
        except Exception:
            pass

    if text.startswith("http://") or text.startswith("https://"):
        raw.append(text)

    for item in URL_RE.findall(text):
        raw.append(item)

    normalized = []
    seen = set()
    for candidate in raw:
        value = _normalize_url(str(candidate or "").strip().strip("'\""))
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        if not _same_host_scope(target_url, value):
            continue
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def ejecutar_katana(target_url: str, auth_params=None):
    """Ejecuta Katana y devuelve únicamente URLs/endpoints válidos y filtrados."""
    katana_bin = _resolve_binary([
        "katana.exe", "katana",
        r"C:\tools\katana\katana.exe",
        r"C:\Program Files\katana\katana.exe",
    ])
    if not katana_bin:
        return [], {"available": False, "executed": False, "count": 0, "error": "katana_not_found"}

    cmd = [katana_bin, "-u", target_url, "-d", "3", "-jc", "-silent", "-nc"]
    cmd = _append_auth_flags(cmd, auth_params=auth_params, support_cookie_flag=False)
    rc, out, err = _run_command(cmd, timeout=360)
    if rc != 0 and not out.strip():
        return [], {"available": True, "executed": False, "count": 0, "error": err[:180]}

    urls = []
    seen = set()
    for line in out.splitlines():
        for candidate in _extract_katana_urls_from_line(line, target_url):
            if candidate in seen:
                continue
            seen.add(candidate)
            urls.append(candidate)

    return urls, {"available": True, "executed": True, "count": len(urls)}


def _parse_httpx_line(line: str):
    text = str(line or "").strip()
    if not text:
        return None
    match = HTTPX_LINE_RE.match(text)
    if not match:
        return None
    url = _normalize_url(match.group(1))
    parts = [p.strip() for p in HTTPX_BRACKETS_RE.findall(match.group(2))]
    if not parts:
        return None
    try:
        status_code = int(parts[0])
    except Exception:
        return None
    tech = parts[1] if len(parts) > 1 else ""
    return {"url": url, "status_code": status_code, "tech": tech}


def _classify_httpx_endpoint(row: dict):
    status = int(row.get("status_code") or 0)
    tech = str(row.get("tech") or "").strip()

    if status in ACTIVE_HTTPX_STATUSES:
        return "active", True
    if status in REDIRECT_HTTPX_STATUSES:
        return "redirect_requires_verification", False
    if status == 404:


        if tech:
            return "discovered_but_unverified_404", False
        return "nonexistent_irrelevant", False
    if status in {400, 406, 415, 422}:
        return "discovered_requires_valid_request", False
    if status >= 500:
        return "server_error_candidate", False
    return "other", False


def verificar_endpoints_httpx(lista_urls, auth_params=None):
    """Verifica en masa URLs de Katana usando HTTPX vía stdin (sin archivos intermedios)."""
    httpx_bin = _resolve_binary([
        "httpx.exe", "httpx",
        r"C:\tools\httpx\httpx.exe",
        r"C:\Program Files\httpx\httpx.exe",
    ])
    if not httpx_bin:
        return [], [], {"available": False, "executed": False, "count": 0, "error": "httpx_not_found"}

    seed_urls = []
    seen = set()
    for item in lista_urls or []:
        value = _normalize_url(item)
        if not value or value in seen:
            continue
        seen.add(value)
        seed_urls.append(value)

    if not seed_urls:
        return [], [], {"available": True, "executed": True, "count": 0}

    payload = "\n".join(seed_urls) + "\n"

    out = ""
    err = ""
    proc_rc = 1
    attempted = [
        _append_auth_flags([httpx_bin, "-silent", "-status-code", "-tech-detect", "-no-color"], auth_params=auth_params, support_cookie_flag=True),
        _append_auth_flags([httpx_bin, "-silent", "-status-code", "-tech", "-no-color"], auth_params=auth_params, support_cookie_flag=True),
        _append_auth_flags([httpx_bin, "-silent", "-status-code", "-tech-detect", "-no-color"], auth_params=auth_params, support_cookie_flag=False),
        _append_auth_flags([httpx_bin, "-silent", "-status-code", "-tech", "-no-color"], auth_params=auth_params, support_cookie_flag=False),
    ]
    for cmd in attempted:
        proc_rc, out, err = _run_command_with_input(cmd, payload, timeout=360)


        if proc_rc == 0 or (out or "").strip():

            if "flag provided but not defined" in (out or "").lower() or "flag provided but not defined" in (err or "").lower():
                continue
            break

    if proc_rc != 0 and not (out or "").strip():
        return [], [], {"available": True, "executed": False, "count": 0, "error": (err or "").strip()[:180]}

    inspected = []
    active_urls = []
    seen_active = set()
    for line in (out or "").splitlines():
        parsed = _parse_httpx_line(line)
        if not parsed:
            continue
        verdict, is_active = _classify_httpx_endpoint(parsed)
        parsed["verdict"] = verdict
        inspected.append(parsed)
        if is_active and parsed["url"] not in seen_active:
            seen_active.add(parsed["url"])
            active_urls.append(parsed["url"])

    return active_urls, inspected, {
        "available": True,
        "executed": True,
        "count": len(inspected),
        "active": len(active_urls),
    }


def escanear_vulnerabilidades_nuclei(lista_urls_activas, auth_params=None, target_url: str = ""):
    """Ejecuta Nuclei con stdin y parsea JSONL a diccionarios Python."""
    nuclei_bin = _resolve_binary([
        "nuclei.exe", "nuclei",
        r"C:\tools\nuclei\nuclei.exe",
        r"C:\Program Files\nuclei\nuclei.exe",
    ])
    if not nuclei_bin:
        return [], {"available": False, "executed": False, "count": 0, "error": "nuclei_not_found"}

    max_targets = max(1, int(os.getenv("BH_NUCLEI_MAX_TARGETS", "6") or 6))
    urls = []
    seen = set()
    dropped_static = 0

    root_target = _normalize_url(target_url)
    if root_target:
        seen.add(root_target)
        urls.append(root_target)

    for item in lista_urls_activas or []:
        value = _normalize_url(item)
        if not value or value in seen:
            continue
        if _looks_like_static_asset(value):
            dropped_static += 1
            continue
        seen.add(value)
        urls.append(value)

    urls = sorted(urls, key=_nuclei_target_priority)
    if len(urls) > max_targets:
        urls = urls[:max_targets]

    if not urls:
        return [], {
            "available": True,
            "executed": True,
            "count": 0,
            "selected_targets": 0,
            "dropped_static": dropped_static,
        }

    cmd = _append_auth_flags(
        [nuclei_bin, "-silent", "-jsonl", "-no-color", "-rate-limit", "75"],
        auth_params=auth_params,
        support_cookie_flag=True,
    )
    payload = "\n".join(urls) + "\n"

    proc_rc, out, err = _run_command_with_input(cmd, payload, timeout=480)
    if proc_rc != 0 and not (out or "").strip():
        return [], {"available": True, "executed": False, "count": 0, "error": (err or "").strip()[:180]}

    findings = []
    for line in (out or "").splitlines():
        text = str(line or "").strip()
        if not text:
            continue
        try:
            findings.append(json.loads(text))
        except Exception:
            continue

    timed_out = bool(proc_rc == 124 or "timed out" in (err or "").lower() or "timeout" in (err or "").lower())
    return findings, {
        "available": True,
        "executed": True,
        "count": len(findings),
        "selected_targets": len(urls),
        "dropped_static": dropped_static,
        "timed_out": timed_out,
    }


def ejecutar_fuzzing_directorios(target_url: str, auth_params=None, wordlist_path: str = ""):
    """Aggressive content discovery using feroxbuster, returning interesting hidden paths."""
    ferox_bin = _resolve_binary([
        "feroxbuster.exe", "feroxbuster",
        r"C:\tools\feroxbuster\feroxbuster.exe",
        r"C:\Program Files\feroxbuster\feroxbuster.exe",
    ])
    ffuf_bin = _resolve_binary([
        "ffuf.exe", "ffuf",
        r"C:\tools\ffuf\ffuf.exe",
        r"C:\Program Files\ffuf\ffuf.exe",
    ])
    if not ferox_bin and not ffuf_bin:
        return [], {"available": False, "executed": False, "count": 0, "error": "ferox_ffuf_not_found"}

    temp_wordlist = ""
    try:
        use_wordlist = str(wordlist_path or "").strip()
        if use_wordlist and os.path.isfile(use_wordlist):
            chosen_wordlist = use_wordlist
        else:
            temp_wordlist = _build_wordlist_file()
            chosen_wordlist = temp_wordlist

        endpoints = []
        seen = set()

        if ferox_bin:
            cmd = [ferox_bin, "--url", target_url, "-w", chosen_wordlist, "--json", "-q", "-t", "50", "-d", "2"]
            cmd = _append_auth_flags(cmd, auth_params=auth_params, support_cookie_flag=False)

            rc, out, err = _run_command(cmd, timeout=360)
            if rc != 0 and not out.strip():
                return [], {"available": True, "executed": False, "count": 0, "error": err[:180]}

            for line in out.splitlines():
                text = str(line or "").strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except Exception:
                    continue
                url = str(row.get("url") or "").strip()
                status = int(row.get("status") or 0)
                if not url or url in seen:
                    continue
                if status not in FUZZ_INTERESTING_STATUSES:
                    continue
                seen.add(url)
                endpoints.append({"url": url, "status": status})

            return endpoints, {"available": True, "executed": True, "count": len(endpoints), "engine": "feroxbuster"}


        normalized = _normalize_auth_params(auth_params)
        cmd = [
            ffuf_bin,
            "-u", f"{str(target_url).rstrip('/')}/FUZZ",
            "-w", chosen_wordlist,
            "-mc", "200,301,302,403",
            "-of", "json",
            "-o", "-",
            "-s",
        ]
        if normalized.get("cookie"):
            cmd.extend(["-b", normalized["cookie"]])
        for header in normalized.get("headers") or []:
            cmd.extend(["-H", header])

        rc, out, err = _run_command(cmd, timeout=360)
        if rc != 0 and not out.strip():
            return [], {"available": True, "executed": False, "count": 0, "error": err[:180]}

        parsed = None
        try:
            parsed = json.loads(out or "{}")
        except Exception:
            parsed = None

        if isinstance(parsed, dict):
            for item in parsed.get("results") or []:
                url = str(item.get("url") or "").strip()
                status = int(item.get("status") or 0)
                if not url or url in seen or status not in FUZZ_INTERESTING_STATUSES:
                    continue
                seen.add(url)
                endpoints.append({"url": url, "status": status})

        return endpoints, {"available": True, "executed": True, "count": len(endpoints), "engine": "ffuf"}
    finally:
        if temp_wordlist:
            try:
                os.unlink(temp_wordlist)
            except Exception:
                pass


def ejecutar_auditoria_completa(target_url: str, auth_params=None, wordlist_path: str = "", force_circl_low_info: bool = False):
    """Orquesta Katana -> Fuzzing -> HTTPX -> Nuclei y devuelve hallazgos listos para reporte."""
    katana_urls, katana_meta = ejecutar_katana(target_url, auth_params=auth_params)
    fuzz_endpoints, fuzz_meta = ejecutar_fuzzing_directorios(
        target_url,
        auth_params=auth_params,
        wordlist_path=wordlist_path,
    )

    fuzz_urls = [str(x.get("url") or "").strip() for x in (fuzz_endpoints or []) if str(x.get("url") or "").strip()]
    merged_urls = list(dict.fromkeys((katana_urls or []) + fuzz_urls))

    active_urls, httpx_inspected, httpx_meta = verificar_endpoints_httpx(merged_urls, auth_params=auth_params)
    nuclei_jsonl, nuclei_meta = escanear_vulnerabilidades_nuclei(active_urls, auth_params=auth_params, target_url=target_url)

    findings, circl_meta = _build_nuclei_findings(
        nuclei_jsonl,
        force_circl_low_info=bool(force_circl_low_info),
    )

    return {
        "katana_urls": katana_urls,
        "fuzz_endpoints": fuzz_endpoints,
        "merged_urls": merged_urls,
        "httpx_active_urls": active_urls,
        "httpx_inspected": httpx_inspected,
        "nuclei_findings": findings,
        "meta": {
            "katana": katana_meta,
            "fuzzing": fuzz_meta,
            "httpx": httpx_meta,
            "nuclei": nuclei_meta,
            "circl": circl_meta,
        },
    }


def _build_wordlist_file():
    handle = tempfile.NamedTemporaryFile(prefix="bh_ferox_", suffix=".txt", mode="w", encoding="utf-8", delete=False)
    try:
        for path in COMMON_WEB_PATHS:
            text = str(path or "").strip()
            if not text:
                continue
            handle.write(text.lstrip("/") + "\n")
    finally:
        handle.close()
    return handle.name


def _run_ferox(target_url: str, depth: str):
    ferox_bin = _resolve_binary([
        "feroxbuster.exe", "feroxbuster",
        r"C:\tools\feroxbuster\feroxbuster.exe",
        r"C:\Program Files\feroxbuster\feroxbuster.exe",
    ])
    if not ferox_bin:
        return [], {"available": False, "executed": False, "count": 0}

    wordlist = _build_wordlist_file()
    try:
        cmd = [ferox_bin, "--url", target_url, "-w", wordlist, "--json", "-q"]
        if str(depth or "").lower() == "rápido":
            cmd.extend(["-t", "20"])
        else:
            cmd.extend(["-t", "50", "-d", "2"])

        rc, out, err = _run_command(cmd, timeout=300)
        if rc != 0 and not out.strip():
            return [], {"available": True, "executed": False, "count": 0, "error": err[:180]}

        endpoints = []
        seen = set()
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            url = str(row.get("url") or "").strip()
            status = int(row.get("status") or 0)
            if not url or url in seen or status == 404:
                continue
            seen.add(url)
            endpoints.append({"url": url, "status": status})

        return endpoints, {"available": True, "executed": True, "count": len(endpoints)}
    finally:
        try:
            os.unlink(wordlist)
        except Exception:
            pass


def _run_nmap_xml(target_url: str, nmap_path: str = ""):
    nmap_bin = nmap_path or _resolve_binary([
        "nmap.exe", "nmap",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ])
    if not nmap_bin:
        return [], {"available": False, "executed": False, "count": 0}

    host = _host_from_target(target_url)
    cmd = [nmap_bin, "-sV", "-F", "--open", "-oX", "-", host]
    rc, out, err = _run_command(cmd, timeout=240)
    if rc != 0 and not out.strip():
        return [], {"available": True, "executed": False, "count": 0, "error": err[:180]}

    ports = []
    try:
        root = ET.fromstring(out)
        for host_node in root.findall("host"):
            ip = ""
            addr = host_node.find("address")
            if addr is not None:
                ip = str(addr.get("addr") or "")
            ports_node = host_node.find("ports")
            if ports_node is None:
                continue
            for port_node in ports_node.findall("port"):
                state = port_node.find("state")
                if state is None or str(state.get("state") or "") != "open":
                    continue
                service = port_node.find("service")
                ports.append({
                    "host": ip,
                    "port": int(port_node.get("portid") or 0),
                    "protocol": str(port_node.get("protocol") or "tcp"),
                    "service": str(service.get("name") or "") if service is not None else "",
                    "product": str(service.get("product") or "") if service is not None else "",
                    "version": str(service.get("version") or "") if service is not None else "",
                })
    except Exception:
        return [], {"available": True, "executed": False, "count": 0, "error": "xml_parse_error"}

    return ports, {"available": True, "executed": True, "count": len(ports)}


def _run_nuclei(target_url: str):
    nuclei_bin = _resolve_binary([
        "nuclei.exe", "nuclei",
        r"C:\tools\nuclei\nuclei.exe",
        r"C:\Program Files\nuclei\nuclei.exe",
    ])
    if not nuclei_bin:
        return [], {"available": False, "executed": False, "count": 0}

    cmd = [nuclei_bin, "-u", target_url, "-jsonl", "-silent"]
    rc, out, err = _run_command(cmd, timeout=300)
    if rc != 0 and not out.strip():
        return [], {"available": True, "executed": False, "count": 0, "error": err[:180]}

    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        findings.append({
            "template_id": str(row.get("template-id") or ""),
            "name": str((row.get("info") or {}).get("name") or row.get("matcher-name") or "Nuclei finding"),
            "severity": str((row.get("info") or {}).get("severity") or "info"),
            "matched_at": str(row.get("matched-at") or row.get("host") or ""),
        })

    return findings, {"available": True, "executed": True, "count": len(findings)}


def _api_wayback_urls(target_url: str, timeout=10.0):
    parsed = urlparse(str(target_url or "").strip())
    host = parsed.hostname or ""
    if not host:
        return []

    params = {
        "url": f"{host}/*",
        "output": "json",
        "fl": "original,statuscode,mimetype",
        "filter": "statuscode:200",
        "collapse": "urlkey",
        "limit": "300",
    }
    try:
        response = requests.get("https://web.archive.org/cdx/search/cdx", params=params, timeout=timeout)
        response.raise_for_status()
        data = response.json() or []
    except Exception:
        return []

    urls = []
    seen = set()
    for row in data[1:]:
        if not isinstance(row, list) or not row:
            continue
        url = str(row[0] or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def _api_crtsh_subdomains(target_url: str, timeout=10.0):
    parsed = urlparse(str(target_url or "").strip())
    host = parsed.hostname or ""
    if not host:
        return []

    base_parts = host.split(".")
    if len(base_parts) < 2:
        return []
    base_domain = ".".join(base_parts[-2:])

    try:
        response = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{base_domain}", "output": "json"},
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json() or []
    except Exception:
        return []

    hosts = set()
    for row in data:
        if not isinstance(row, dict):
            continue
        names = str(row.get("name_value") or "")
        for item in names.splitlines():
            value = item.strip().lower()
            if not value or "*" in value:
                continue
            if value.endswith(base_domain):
                hosts.add(value)

    urls = []
    for sub in sorted(hosts):
        urls.append(f"https://{sub}")
    return urls[:200]


def run_external_tools_pipeline(
    target_url: str,
    existing_results: list,
    depth: str = "Completo",
    nmap_path: str = "",
    run_nmap_stage: bool = True,
    prefetched_web_chain: dict | None = None,
    auth_params: dict | None = None,
    fuzz_wordlist_path: str = "",
    force_circl_low_info: bool = False,
):
    """Execute external recon pipeline and return normalized rows.

    Returns:
      dict with rows + summary metrics
    """
    rows = []
    internal_sigs = _internal_signatures(existing_results)
    external_sigs = set()
    consolidated = 0


    normalized_auth = _normalize_auth_params(auth_params)
    prefer_prefetched = bool(prefetched_web_chain and isinstance(prefetched_web_chain, dict) and not normalized_auth.get("headers"))

    if prefer_prefetched and (prefetched_web_chain.get("katana_urls") or []):
        katana_urls = prefetched_web_chain.get("katana_urls") or []
        katana_meta = (prefetched_web_chain.get("meta") or {}).get("katana") or {
            "available": True,
            "executed": True,
            "count": len(katana_urls),
        }
    else:
        katana_urls, katana_meta = ejecutar_katana(target_url, auth_params=normalized_auth)

    fuzz_endpoints, fuzz_meta = ejecutar_fuzzing_directorios(
        target_url,
        auth_params=normalized_auth,
        wordlist_path=fuzz_wordlist_path,
    )
    fuzz_urls = [str(item.get("url") or "").strip() for item in (fuzz_endpoints or []) if str(item.get("url") or "").strip()]
    merged_urls = list(dict.fromkeys((katana_urls or []) + fuzz_urls))

    httpx_active_urls, httpx_inspected, httpx_meta = verificar_endpoints_httpx(merged_urls, auth_params=normalized_auth)
    nuclei_jsonl, nuclei_meta = escanear_vulnerabilidades_nuclei(httpx_active_urls, auth_params=normalized_auth, target_url=target_url)
    force_from_env = str(os.getenv("BH_FORCE_CIRCL_LOW_INFO", "")).strip().lower() in {"1", "true", "yes", "on"}
    nuclei_findings, circl_meta = _build_nuclei_findings(
        nuclei_jsonl,
        force_circl_low_info=bool(force_circl_low_info or force_from_env),
    )

    api_urls = []
    if katana_meta.get("executed"):
        rows.append({
            "control": "Pipeline externo - Katana",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Crawling dinámico con filtrado anti-ruido para extraer solo rutas útiles en alcance.",
            "evidence": f"URLs descubiertas: {katana_meta.get('count', 0)}",
            "recommendation": "Cruzar endpoints descubiertos con controles de autenticación y autorización.",
        })
    else:
        wayback = _api_wayback_urls(target_url)
        crt_urls = _api_crtsh_subdomains(target_url)
        api_urls = list(dict.fromkeys((wayback or []) + (crt_urls or [])))
        if api_urls:
            rows.append({
                "control": "Pipeline API - Recon pasivo",
                "status": "Detectado",
                "severity": "Informativa",
                "description": "Recon externo por APIs públicas (Wayback/crt.sh) al no disponer de Katana local.",
                "evidence": f"URLs/subdominios recuperados: {len(api_urls)}",
                "recommendation": "Validar manualmente activos recuperados y filtrar terceros fuera de alcance.",
            })

    if httpx_meta.get("executed"):
        verdict_counts = {}
        for item in httpx_inspected:
            verdict = str(item.get("verdict") or "other")
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        rows.append({
            "control": "Pipeline externo - HTTPX",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Verificación masiva por estado HTTP para separar rutas activas, redirecciones y 404 no relevantes.",
            "evidence": (
                f"Inspeccionadas={httpx_meta.get('count', 0)} | Activas={httpx_meta.get('active', 0)} | "
                f"404_no_validas={verdict_counts.get('discovered_but_unverified_404', 0)} | "
                f"Redirect_requiere_validacion={verdict_counts.get('redirect_requires_verification', 0)}"
            ),
            "recommendation": "Usar solo rutas activas para Nuclei y tratar 3xx/404 como evidencia de validación pendiente.",
        })

        for item in httpx_inspected[:30]:
            verdict = str(item.get("verdict") or "other")
            if verdict == "nonexistent_irrelevant":
                continue

            status_code = int(item.get("status_code") or 0)
            sev = "Informativa"
            description = "Endpoint activo y candidato para pruebas automáticas."
            recommendation = "Mantener en scope de pruebas y validar controles de seguridad específicos de la ruta."
            report_status = "Detectado"

            if verdict == "redirect_requires_verification":
                description = "Ruta con redirección; no se considera válida para ataque directo sin verificar destino final."
                recommendation = "Resolver flujo de redirección/autenticación y revalidar endpoint final."
                report_status = "Comprobado"
            elif verdict == "discovered_but_unverified_404":
                sev = "Media"
                description = "Ruta descubierta con 404 pero con señal de tecnología; posible endpoint real sin contexto válido."
                recommendation = "Probar con sesión autenticada, método correcto y parámetros válidos antes de descartarla."
                report_status = "No verificado"
            elif verdict == "discovered_requires_valid_request":
                sev = "Media"
                description = "Ruta descubierta que exige formato/método válido (4xx funcional)."
                recommendation = "Repetir prueba con método HTTP y payload acordes al endpoint."
                report_status = "No verificado"
            elif verdict == "server_error_candidate":
                sev = "Media"
                description = "Ruta descubierta con error de servidor; posible fallo explotable o manejo deficiente de errores."
                recommendation = "Reproducir con trazas controladas y revisar robustez de backend."
                report_status = "Posible hallazgo"

            rows.append({
                "control": "Endpoint verificado por HTTPX",
                "status": report_status,
                "severity": sev,
                "description": description,
                "evidence": f"URL: {item.get('url')} | HTTP: {status_code} | Veredicto: {verdict}",
                "recommendation": recommendation,
            })

    ferox_meta = fuzz_meta
    if fuzz_meta.get("executed"):
        rows.append({
            "control": "Pipeline externo - Fuzzing",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Fuerza bruta de contenidos para descubrir rutas/archivos ocultos no visibles por crawling HTML.",
            "evidence": f"Rutas ocultas interesantes: {fuzz_meta.get('count', 0)}",
            "recommendation": "Validar acceso y exposición de rutas no documentadas.",
        })
        for item in (fuzz_endpoints or [])[:20]:
            rows.append({
                "control": "Ruta descubierta por fuzzing",
                "status": "Detectado",
                "severity": "Media" if int(item.get("status") or 0) in {200, 401, 403} else "Informativa",
                "description": "Ruta descubierta mediante fuzzing de diccionario.",
                "evidence": f"URL: {item.get('url')} | HTTP: {item.get('status')}",
                "recommendation": "Validar control de acceso y exposición de contenido en esta ruta.",
            })
    elif api_urls:
        for url in api_urls[:20]:
            rows.append({
                "control": "Ruta descubierta por API pasiva",
                "status": "Detectado",
                "severity": "Informativa",
                "description": "Ruta/activo descubierto con fuentes públicas externas.",
                "evidence": f"URL: {url}",
                "recommendation": "Comprobar pertenencia al alcance y aplicar hardening si sigue expuesto.",
            })

    nmap_ports = []
    nmap_meta = {"available": False, "executed": False, "count": 0}
    if run_nmap_stage:
        nmap_ports, nmap_meta = _run_nmap_xml(target_url, nmap_path=nmap_path)
        if nmap_meta.get("executed"):
            rows.append({
                "control": "Pipeline externo - Nmap",
                "status": "Detectado",
                "severity": "Informativa",
                "description": "Descubrimiento de puertos/servicios con banner grabbing en modo rápido.",
                "evidence": f"Servicios abiertos detectados: {nmap_meta.get('count', 0)}",
                "recommendation": "Correlacionar servicios/versiones con CVEs y exposición real.",
            })
            for p in nmap_ports[:15]:
                rows.append({
                    "control": f"Servicio detectado en puerto {p.get('port')}",
                    "status": "Detectado",
                    "severity": "Media" if int(p.get("port") or 0) in {21, 22, 3389, 5432, 3306, 8080} else "Informativa",
                    "description": "Servicio detectado en infraestructura objetivo por escaneo externo.",
                    "evidence": (
                        f"Host: {p.get('host') or _host_from_target(target_url)} | "
                        f"Puerto: {p.get('port')}/{p.get('protocol')} | "
                        f"Servicio: {p.get('service')} | Producto: {p.get('product')} | Versión: {p.get('version')}"
                    ),
                    "recommendation": "Aplicar hardening y segmentación para servicios no estrictamente necesarios.",
                })

    if nuclei_meta.get("executed"):
        rows.append({
            "control": "Pipeline externo - Nuclei",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Escaneo basado en templates sobre endpoints activos validados previamente por HTTPX.",
            "evidence": (
                f"Targets activos para Nuclei: {len(httpx_active_urls)} | "
                f"Seleccionados para escaneo: {nuclei_meta.get('selected_targets', 0)} | "
                f"Assets filtrados: {nuclei_meta.get('dropped_static', 0)} | "
                f"Findings Nuclei: {nuclei_meta.get('count', 0)}"
            ),
            "recommendation": "Consolidar resultados con motor interno para reducir falsos positivos y duplicados.",
        })

        for finding in nuclei_findings:
            sig = _normalize_sig(f"{finding.get('template_id')} {finding.get('name')}")
            if not sig:
                continue
            if sig in internal_sigs or sig in external_sigs:
                consolidated += 1
                continue
            external_sigs.add(sig)

            rows.append({
                "control": f"Nuclei: {finding.get('name')}",
                "status": "Posible hallazgo",
                "severity": _severity_es(finding.get("severity")),
                "description": "Hallazgo detectado por template externo de seguridad.",
                "evidence": (
                    f"Template: {finding.get('template_id')} | "
                    f"Target: {finding.get('matched_at')} | "
                    f"CVEs: {', '.join(finding.get('cve_ids') or []) or 'N/A'}"
                ),
                "recommendation": (
                    "Validar manualmente reproducibilidad y aplicar mitigación específica del control."
                    if not (finding.get("circl") or [])
                    else "Validar explotación priorizando referencias CIRCL asociadas al CVE detectado."
                ),
            })

            for circl_item in (finding.get("circl") or [])[:3]:
                refs = circl_item.get("references") or []
                rows.append({
                    "control": f"CIRCL CVE: {circl_item.get('id')}",
                    "status": "Comprobado",
                    "severity": _severity_es(finding.get("severity")),
                    "description": "CVE correlacionado automáticamente desde CIRCL para priorización de explotación.",
                    "evidence": (
                        f"CVSS: {circl_item.get('cvss')} | "
                        f"Resumen: {str(circl_item.get('summary') or '')[:180]} | "
                        f"Refs: {', '.join(refs[:2]) or 'N/A'}"
                    ),
                    "recommendation": "Revisar advisory y PoC públicos enlazados antes de ejecutar pruebas activas.",
                })

    rows.append({
        "control": "Pipeline externo - Consolidación",
        "status": "Comprobado",
        "severity": "Informativa",
        "description": "Consolidación y deduplicación estricta aplicada sobre salidas de herramientas externas.",
        "evidence": (
            f"Katana={katana_meta.get('count', 0)} | HTTPX_activos={len(httpx_active_urls)} | "
            f"Ferox={ferox_meta.get('count', 0)} | Nmap={nmap_meta.get('count', 0)} | Nuclei={nuclei_meta.get('count', 0)} | "
            f"Consolidados por duplicidad={consolidated}"
        ),
        "recommendation": "Reportar únicamente hallazgos netos para evitar inflación de criticidad en comité.",
    })

    return {
        "rows": rows,
        "katana_urls": katana_urls,
        "fuzz_endpoints": fuzz_endpoints,
        "merged_urls": merged_urls,
        "httpx_active_urls": httpx_active_urls,
        "httpx_inspected": httpx_inspected,
        "meta": {
            "katana": katana_meta,
            "httpx": httpx_meta,
            "ferox": ferox_meta,
            "fuzzing": fuzz_meta,
            "nmap": nmap_meta,
            "nuclei": nuclei_meta,
            "circl": circl_meta,
            "deduped": consolidated,
        },
    }


def _cli_main():
    parser = argparse.ArgumentParser(description="External recon pipeline (Katana -> Fuzzing -> HTTPX -> Nuclei)")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--cookie", default="", help='Cookie string, e.g. "session=abc123"')
    parser.add_argument("--auth-header", default="", help='Authorization header, e.g. "Authorization: Bearer <token>"')
    parser.add_argument("--header", action="append", default=[], help="Extra header (repeatable)")
    parser.add_argument("--wordlist", default="", help="Optional custom wordlist path for fuzzing")
    parser.add_argument("--force-circl-low-info", action="store_true", help="Also query CIRCL for low/info findings")
    args = parser.parse_args()

    auth_params = {
        "cookie": str(args.cookie or "").strip(),
        "auth_header": str(args.auth_header or "").strip(),
        "headers": [str(h or "").strip() for h in (args.header or []) if str(h or "").strip()],
    }

    result = ejecutar_auditoria_completa(
        target_url=str(args.target or "").strip(),
        auth_params=auth_params,
        wordlist_path=str(args.wordlist or "").strip(),
        force_circl_low_info=bool(args.force_circl_low_info),
    )

    payload = {
        "target": args.target,
        "katana_urls": len(result.get("katana_urls") or []),
        "fuzz_endpoints": len(result.get("fuzz_endpoints") or []),
        "merged_urls": len(result.get("merged_urls") or []),
        "httpx_active_urls": len(result.get("httpx_active_urls") or []),
        "nuclei_findings": len(result.get("nuclei_findings") or []),
        "meta": result.get("meta") or {},
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _cli_main()
