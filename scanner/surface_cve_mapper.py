# Modulo que relaciona CVE con rutas y superficie DOM descubierta del objetivo.

"""
surface_cve_mapper.py
Cruza cada CVE/familia de exploit con la superficie descubierta del objetivo
para indicar exactamente en qué ruta y qué elemento del DOM se podría explotar.

Devuelve una lista de HitContext:
  {
    "url":        str   – URL canónica de la página afectada
    "dom_target": str   – descripción del elemento DOM (p.ej. 'input[name=email] en <form action=/login>')
    "field":      str   – nombre del campo/parámetro relevante (si aplica)
    "context":    str   – frase corta explicativa para mostrar en UI
    "confidence": float – 0.0–1.0 grado de certeza del mapeo
  }
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import List, Dict, Any






def _safe(value: Any) -> str:
    return str(value or "").strip()


def _path(url: str) -> str:
    return urlparse(_safe(url)).path.lower()


def _page_url(page: dict) -> str:
    return _safe(page.get("final_url") or page.get("url"))


def _forms(page: dict) -> list:
    return list(page.get("forms") or [])


def _html(page: dict) -> str:
    blobs = [
        _safe(page.get("html")),
        _safe(page.get("rendered_html")),
        _safe((page.get("browser_runtime") or {}).get("html")),
    ]
    return " ".join(b for b in blobs if b).lower()


def _inputs(page: dict) -> list:
    """Flatten all <input> fields from forms into a list of (name, type, form_action)."""
    result = []
    for form in _forms(page):
        action = _safe(form.get("action") or _page_url(page))
        for field in (form.get("fields") or form.get("inputs") or []):
            result.append({
                "name": _safe(field.get("name") or field.get("id")),
                "type": _safe(field.get("type") or "text").lower(),
                "action": action,
            })
    return result


def _has_input_type(page: dict, input_type: str) -> bool:
    t = input_type.lower()
    for inp in _inputs(page):
        if inp["type"] == t:
            return True

    return f'type="{t}"' in _html(page) or f"type='{t}'" in _html(page)


def _param_names_in_url(url: str) -> list[str]:
    from urllib.parse import parse_qs
    query = urlparse(_safe(url)).query
    return list(parse_qs(query).keys())






def _match_sqli(pages: list) -> list:
    hits = []
    for page in pages:
        url = _page_url(page)
        path = _path(url)
        h = _html(page)
        for inp in _inputs(page):
            iname = inp["name"].lower()
            itype = inp["type"]
            if itype in ("text", "email", "number", "search", "hidden", "tel") or iname in (
                "id", "search", "q", "query", "username", "user", "email", "order", "sort",
                "page", "category", "cat", "product", "item", "filter",
            ):
                hits.append({
                    "url": url,
                    "dom_target": f"<input name='{inp['name']}' type='{inp['type']}'> en form[action='{inp['action']}']",
                    "field": inp["name"],
                    "context": (
                        f"Al enviar el campo '{inp['name']}' en {_path(url or url)}, "
                        f"un payload SQL podría afectar la consulta de backend."
                    ),
                    "confidence": 0.75,
                })

        for param in _param_names_in_url(url):
            hits.append({
                "url": url,
                "dom_target": f"Parámetro URL ?{param}=",
                "field": param,
                "context": (
                    f"El parámetro ?{param}= en {_path(url)} podría ser vectorizado con SQLi."
                ),
                "confidence": 0.60,
            })
        if not hits and ("api" in path or "graphql" in path):
            hits.append({
                "url": url,
                "dom_target": "Endpoint API/GraphQL",
                "field": "",
                "context": f"Endpoint {_path(url)} podría recibir consultas con SQLi en el cuerpo.",
                "confidence": 0.50,
            })
    return hits


def _match_xss(pages: list) -> list:
    hits = []
    xss_input_types = ("text", "search", "email", "url", "textarea")
    xss_name_hints = ("q", "query", "search", "comment", "message", "name", "title",
                      "description", "feedback", "review", "content", "body")
    for page in pages:
        url = _page_url(page)
        for inp in _inputs(page):
            iname = inp["name"].lower()
            itype = inp["type"]
            if itype in xss_input_types or iname in xss_name_hints:
                hits.append({
                    "url": url,
                    "dom_target": f"<input name='{inp['name']}' type='{itype}'> en form[action='{inp['action']}']",
                    "field": inp["name"],
                    "context": (
                        f"El campo '{inp['name']}' en {_path(url)} refleja o almacena contenido "
                        "sin sanitizar: punto de inyección XSS."
                    ),
                    "confidence": 0.80,
                })
        h = _html(page)
        if "<textarea" in h:
            hits.append({
                "url": url,
                "dom_target": "<textarea> (área de texto)",
                "field": "textarea",
                "context": f"Área de texto en {_path(url)}: candidata a XSS almacenado.",
                "confidence": 0.70,
            })
        for param in _param_names_in_url(url):
            hits.append({
                "url": url,
                "dom_target": f"Parámetro URL ?{param}=",
                "field": param,
                "context": f"Parámetro ?{param}= en {_path(url)}: candidato a XSS reflejado.",
                "confidence": 0.65,
            })
    return hits


def _match_file_upload(pages: list) -> list:
    hits = []
    for page in pages:
        url = _page_url(page)
        if _has_input_type(page, "file"):
            field_name = ""
            for inp in _inputs(page):
                if inp["type"] == "file":
                    field_name = inp["name"]
                    break
            hits.append({
                "url": url,
                "dom_target": f"<input type='file' name='{field_name}'> en {_path(url)}",
                "field": field_name,
                "context": (
                    f"El formulario de subida de archivos en {_path(url)} (campo '{field_name}') "
                    "puede ser explotado si el backend no valida tamaño, tipo MIME o contenido."
                ),
                "confidence": 0.90,
            })
    return hits


def _match_auth_bypass(pages: list) -> list:
    hits = []
    for page in pages:
        url = _page_url(page)
        path = _path(url)
        classification = _safe(page.get("classification")).lower()
        if classification == "auth" or any(tok in path for tok in ("/login", "/signin", "/auth", "/iniciar-sesion")):
            pwd_field = ""
            user_field = ""
            action = ""
            for inp in _inputs(page):
                if inp["type"] == "password":
                    pwd_field = inp["name"]
                    action = inp["action"]
                elif inp["type"] in ("text", "email") and not user_field:
                    user_field = inp["name"]
            dom = (
                f"<input name='{user_field}'> + <input type='password' name='{pwd_field}'>"
                if pwd_field else "Formulario de login"
            )
            hits.append({
                "url": url,
                "dom_target": dom + (f" en form[action='{action}']" if action else ""),
                "field": f"{user_field}, {pwd_field}".strip(", "),
                "context": (
                    f"El formulario de autenticación en {_path(url)} es el punto de entrada "
                    "para bypass de credenciales, inyección en campo de usuario/contraseña o fuerza bruta."
                ),
                "confidence": 0.85,
            })
    return hits


def _match_csrf(pages: list) -> list:
    hits = []
    csrf_token_hints = ("csrf", "token", "_token", "nonce", "xsrf", "authenticity_token")
    for page in pages:
        url = _page_url(page)
        for form in _forms(page):
            action = _safe(form.get("action") or url)
            method = _safe(form.get("method") or "GET").upper()
            if method != "POST":
                continue
            fields = form.get("fields") or form.get("inputs") or []
            has_csrf_token = any(
                any(hint in _safe(f.get("name") or "").lower() for hint in csrf_token_hints)
                for f in fields
            )
            if not has_csrf_token:
                hits.append({
                    "url": url,
                    "dom_target": f"<form method='POST' action='{action}'> sin token CSRF",
                    "field": "—",
                    "context": (
                        f"El formulario POST en {_path(action)} no tiene token CSRF detectado: "
                        "un atacante podría disparar la acción desde otra página."
                    ),
                    "confidence": 0.80,
                })
    return hits


def _match_path_traversal(pages: list) -> list:
    hits = []
    path_params = ("file", "path", "dir", "folder", "doc", "documento", "filename",
                   "resource", "page", "template", "include", "load")
    for page in pages:
        url = _page_url(page)
        for param in _param_names_in_url(url):
            if param.lower() in path_params:
                hits.append({
                    "url": url,
                    "dom_target": f"Parámetro URL ?{param}=",
                    "field": param,
                    "context": (
                        f"El parámetro ?{param}= en {_path(url)} puede ser explotado con ../../../etc/passwd "
                        "si el backend construye rutas de archivo sin validar."
                    ),
                    "confidence": 0.75,
                })
        for inp in _inputs(page):
            if inp["name"].lower() in path_params:
                hits.append({
                    "url": url,
                    "dom_target": f"<input name='{inp['name']}'> en form[action='{inp['action']}']",
                    "field": inp["name"],
                    "context": (
                        f"El campo '{inp['name']}' en {_path(url)} puede usarse para path traversal "
                        "si el valor se pasa directamente a una función de lectura de archivos."
                    ),
                    "confidence": 0.70,
                })
    return hits


def _match_rce(pages: list) -> list:
    hits = []
    rce_path_hints = ("admin", "upload", "exec", "eval", "shell", "cmd", "command",
                      "run", "execute", "script", "graphql", "api")
    rce_param_hints = ("cmd", "command", "exec", "run", "code", "eval", "input",
                       "payload", "expression", "template")
    for page in pages:
        url = _page_url(page)
        path = _path(url)
        classification = _safe(page.get("classification")).lower()
        if any(hint in path for hint in rce_path_hints) or classification in (
            "admin_candidate", "api_candidate"
        ):
            hits.append({
                "url": url,
                "dom_target": f"Endpoint {_path(url)}",
                "field": "",
                "context": (
                    f"La ruta {_path(url)} (clasificada como '{classification}') es candidata a RCE: "
                    "explorar parámetros de ejecución de comandos o inyección de plantillas."
                ),
                "confidence": 0.60,
            })
        for param in _param_names_in_url(url):
            if param.lower() in rce_param_hints:
                hits.append({
                    "url": url,
                    "dom_target": f"Parámetro URL ?{param}=",
                    "field": param,
                    "context": (
                        f"El parámetro ?{param}= en {_path(url)} podría ejecutar código si se inyectan "
                        "expresiones de plantilla o comandos OS sin sanitizar."
                    ),
                    "confidence": 0.70,
                })
    return hits


def _match_ssrf(pages: list) -> list:
    hits = []
    ssrf_param_hints = ("url", "uri", "src", "source", "dest", "destination", "href",
                        "redirect", "return", "link", "endpoint", "callback", "webhook", "proxy")
    for page in pages:
        url = _page_url(page)
        for param in _param_names_in_url(url):
            if param.lower() in ssrf_param_hints:
                hits.append({
                    "url": url,
                    "dom_target": f"Parámetro URL ?{param}=",
                    "field": param,
                    "context": (
                        f"El parámetro ?{param}= en {_path(url)} acepta una URL: "
                        "candidato a SSRF si el servidor realiza peticiones a esa URL."
                    ),
                    "confidence": 0.75,
                })
        for inp in _inputs(page):
            if inp["name"].lower() in ssrf_param_hints:
                hits.append({
                    "url": url,
                    "dom_target": f"<input name='{inp['name']}'> en form[action='{inp['action']}']",
                    "field": inp["name"],
                    "context": (
                        f"El campo '{inp['name']}' en {_path(url)} acepta URLs: "
                        "el servidor podría hacer fetch a destinos internos (SSRF)."
                    ),
                    "confidence": 0.70,
                })
    return hits


def _match_dos(pages: list, target_url: str) -> list:
    hits = []
    upload_pages = [p for p in pages if _has_input_type(p, "file")]
    for page in upload_pages:
        url = _page_url(page)
        hits.append({
            "url": url,
            "dom_target": f"<input type='file'> en {_path(url)}",
            "field": "file",
            "context": (
                f"Subir un archivo superior al límite en {_path(url)} puede explotar "
                "una vulnerabilidad de DoS si el backend no limita el tamaño antes de procesar."
            ),
            "confidence": 0.65,
        })
    if not hits:
        hits.append({
            "url": target_url,
            "dom_target": "Cualquier endpoint con cuerpo de petición grande",
            "field": "",
            "context": (
                f"Enviar peticiones muy grandes o de alta frecuencia al endpoint raíz {_path(target_url)} "
                "puede provocar agotamiento de recursos."
            ),
            "confidence": 0.40,
        })
    return hits






_FAMILY_MATCHERS = {
    "SQL Injection":                    _match_sqli,
    "Cross-Site Scripting (XSS)":       _match_xss,
    "Remote Code Execution (RCE)":      _match_rce,
    "Buffer Overflow":                  _match_rce,
    "Authentication Bypass":            _match_auth_bypass,
    "Path Traversal / LFI":             _match_path_traversal,
    "Cross-Site Request Forgery (CSRF)":_match_csrf,
    "Server-Side Request Forgery (SSRF)":_match_ssrf,
    "Insecure Deserialization":         _match_rce,
    "XML External Entity (XXE)":        _match_rce,
    "Open Redirect":                    _match_ssrf,
    "Denial of Service (DoS)":          _match_dos,
}


def map_cve_to_surface(
    family: str,
    pages: list,
    target_url: str = "",
    max_hits: int = 4,
) -> List[Dict]:
    """
    Returns up to max_hits HitContext dicts for the given exploit family.
    """
    matcher = _FAMILY_MATCHERS.get(family)
    if matcher is None:

        results = []
        seen = set()
        for page in pages or []:
            url = _page_url(page)
            if url and url not in seen and _forms(page):
                seen.add(url)
                results.append({
                    "url": url,
                    "dom_target": f"Formulario en {_path(url)}",
                    "field": "",
                    "context": f"La familia '{family}' podría afectar este formulario.",
                    "confidence": 0.35,
                })
        return results[:max_hits]

    try:
        if family == "Denial of Service (DoS)":
            raw = matcher(pages or [], target_url)
        else:
            raw = matcher(pages or [])
    except Exception:
        return []


    seen = set()
    unique = []
    for hit in sorted(raw, key=lambda h: h.get("confidence", 0), reverse=True):
        key = (_safe(hit.get("url")), _safe(hit.get("field")))
        if key not in seen:
            seen.add(key)
            unique.append(hit)

    return unique[:max_hits]


def enrich_suggestions_with_surface(
    suggestions: List[Dict],
    pages: list,
    target_url: str = "",
) -> List[Dict]:
    """
    In-place enrichment: adds 'affected_surface' key to each suggestion.
    """
    for sug in suggestions or []:
        family = _safe(sug.get("family"))
        hits = map_cve_to_surface(family, pages, target_url=target_url, max_hits=4)
        sug["affected_surface"] = hits

        if hits and "TARGET" in _safe(sug.get("poc")):
            best_url = _safe(hits[0].get("url"))
            if best_url:
                sug["poc"] = _safe(sug.get("poc")).replace(
                    "https://TARGET", best_url
                ).replace(
                    "{target_url}", best_url
                )
    return suggestions
