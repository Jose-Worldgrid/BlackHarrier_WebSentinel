# Modulo de correlacion de evidencia para priorizar riesgos y exposiciones tecnicas.

import json
import os
import re

from scanner.http_client import HttpClient


DB_PATH = os.path.join(os.path.dirname(__file__), "data", "cve_fingerprint_db.json")


def _major_minor_patch(version: str):
    try:
        parts = [int(x) for x in str(version).split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    except Exception:
        return (0, 0, 0)


def _is_old(tech: str, version: str) -> bool:
    v = _major_minor_patch(version)
    if tech == "apache":
        return v < (2, 4, 58)
    if tech == "nginx":
        return v < (1, 24, 0)
    if tech == "php":
        return v < (8, 1, 0)
    return False


def _load_rules():
    if not os.path.exists(DB_PATH):
        return {"version_rules": [], "header_rules": []}
    try:
        with open(DB_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return {
                "version_rules": data.get("version_rules", []),
                "header_rules": data.get("header_rules", []),
            }
    except Exception:
        return {"version_rules": [], "header_rules": []}


def _is_version_leq(version: str, max_inclusive: str) -> bool:
    return _major_minor_patch(version) <= _major_minor_patch(max_inclusive)


def scan_vulnerability_correlation(url: str, profile: str = "standard"):
    """Heuristic, Nessus-inspired exposure correlation from public fingerprints."""
    client = HttpClient()

    try:
        response = client.get(url)
    except Exception as exc:
        return [
            {
                "control": "Correlación de exposición tecnológica",
                "status": "Error",
                "severity": "Media",
                "description": "No se pudo obtener respuesta HTTP para correlación de exposición.",
                "evidence": str(exc),
                "recommendation": "Verificar conectividad y repetir con alcance autorizado estable.",
            }
        ]

    headers = " ".join([f"{k}: {v}" for k, v in response.headers.items()])
    body = response.text or ""
    body_limit = 9000 if str(profile).lower() == "deep" else 6000
    fingerprint_blob = f"{headers}\n{body[:body_limit]}"

    rules = _load_rules()

    advisories = []
    for rule in rules.get("version_rules", []):
        pattern = str(rule.get("pattern") or "")
        match = re.search(pattern, fingerprint_blob, flags=re.IGNORECASE)
        if not match:
            continue
        version = match.group(1)
        tech = str(rule.get("technology") or "")
        max_inclusive = str(rule.get("max_inclusive") or "")

        old_by_builtin = _is_old(tech, version)
        old_by_rule = bool(max_inclusive and _is_version_leq(version, max_inclusive))
        if old_by_builtin or old_by_rule:
            advisories.append({
                "id": str(rule.get("id") or "CVE-CORR-UNKNOWN"),
                "title": str(rule.get("title") or f"{tech} potentially outdated"),
                "severity": str(rule.get("severity") or "Media"),
                "version": version,
                "recommendation": str(rule.get("recommendation") or "Upgrade to a supported release."),
            })

    missing = []
    for rule in rules.get("header_rules", []):
        header_name = str(rule.get("header") or "")
        if not header_name:
            continue
        if not str(response.headers.get(header_name, "")).strip():
            missing.append(rule)


    exposed_leaks = []
    for rule in rules.get("exposed_header_rules", []):
        header_name = str(rule.get("header") or "")
        if not header_name:
            continue
        value = str(response.headers.get(header_name, "")).strip()
        if value:
            exposed_leaks.append({**rule, "value": value})

    if not advisories and not missing and not exposed_leaks:
        return [{
            "control": "Correlación de exposición tecnológica",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron señales de exposición tecnológica obsoleta en el fingerprinting.",
            "evidence": "Sin coincidencias de versión ni cabeceras de seguridad ausentes en este análisis.",
            "recommendation": "Mantener gestión de parches y contrastar con escáner autenticado periódicamente.",
        }]

    results = []


    for advisory in advisories[:8]:
        sev = str(advisory.get("severity") or "Media")
        results.append({
            "control": f"Tecnología desactualizada: {advisory.get('id', '')}",
            "status": "Posible hallazgo",
            "severity": sev,
            "description": advisory.get("title", ""),
            "evidence": (
                f"Versión detectada: {advisory['version']} | "
                f"ID: {advisory.get('id', '')} | "
                f"Fuente: fingerprinting HTTP"
            ),
            "recommendation": advisory.get("recommendation", "Actualizar a la versión más reciente soportada."),
        })


    if missing:
        for rule in missing[:6]:
            results.append({
                "control": f"Cabecera de seguridad ausente: {rule.get('header', '')}",
                "status": "Posible hallazgo",
                "severity": str(rule.get("severity") or "Media"),
                "description": rule.get("title", f"Cabecera {rule.get('header','')} no presente."),
                "evidence": (
                    f"Cabecera '{rule.get('header','')}' ausente en respuesta HTTP | "
                    f"URL: {url}"
                ),
                "recommendation": str(rule.get("recommendation") or "Añadir cabecera de seguridad."),
            })


    for leak in exposed_leaks[:4]:
        results.append({
            "control": f"Fuga de versión: {leak.get('header', '')}",
            "status": "Posible hallazgo",
            "severity": str(leak.get("severity") or "Media"),
            "description": leak.get("title", ""),
            "evidence": f"{leak.get('header', '')}: {leak.get('value', '')} | URL: {url}",
            "recommendation": str(leak.get("recommendation") or "Suprimir cabecera informativa."),
        })

    return results
