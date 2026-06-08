# Modulo de procesamiento y normalizacion de salidas de herramientas estilo Kali.

import os
import re
import statistics
import subprocess
from urllib.parse import urlparse

from scanner.tool_detection import resolve_binary


AUTH_PATH_HINTS = (
    "login", "signin", "auth", "session", "token", "oauth", "account", "usuario", "acceso", "graphql"
)

SQL_ERROR_PATTERNS = (
    "sql syntax", "sqlstate", "mysql", "mariadb", "postgresql", "psql", "sqlite", "odbc", "jdbc",
    "unclosed quotation", "quoted string not properly terminated", "database error", "syntax error near"
)

DB_TECH_PATTERNS = {
    "mysql": ("mysql", "mariadb"),
    "postgresql": ("postgresql", "postgres", "psql"),
    "sqlite": ("sqlite",),
    "mssql": ("sql server", "mssql", "sqlsrv"),
    "oracle": ("oracle", "ora-"),
    "mongodb": ("mongodb", "mongo"),
}


def _startupinfo_hidden():
    if os.name != "nt":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0
    return info


def _run_command(cmd, timeout=30):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            startupinfo=_startupinfo_hidden(),
        )
        return {
            "ok": result.returncode == 0,
            "stdout": str(result.stdout or ""),
            "stderr": str(result.stderr or ""),
            "returncode": int(result.returncode),
        }
    except Exception as exc:
        return {
            "ok": False,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "returncode": -1,
        }


def _is_auth_like_event(event):
    method = str(event.get("method") or "").upper()
    final_url = str(event.get("final_url") or event.get("url") or "").lower()
    content_type = str(event.get("content_type") or "").lower()
    if method != "POST":
        return False
    if any(token in final_url for token in AUTH_PATH_HINTS):
        return True
    return "application/json" in content_type or "x-www-form-urlencoded" in content_type


def _detect_db_signatures(text):
    lower = str(text or "").lower()
    found = set()
    if not lower:
        return found
    for db_name, patterns in DB_TECH_PATTERNS.items():
        if any(pattern in lower for pattern in patterns):
            found.add(db_name)
    return found


def infer_login_database_interaction(raw_events):
    events = list(raw_events or [])
    auth_posts = [e for e in events if _is_auth_like_event(e)]
    all_posts = [e for e in events if str(e.get("method") or "").upper() == "POST"]
    all_gets = [e for e in events if str(e.get("method") or "").upper() == "GET"]

    post_latencies = [int(e.get("duration_ms") or 0) for e in auth_posts if int(e.get("duration_ms") or 0) > 0]
    get_latencies = [int(e.get("duration_ms") or 0) for e in all_gets if int(e.get("duration_ms") or 0) > 0]

    post_median = int(statistics.median(post_latencies)) if post_latencies else 0
    get_median = int(statistics.median(get_latencies)) if get_latencies else 0
    slow_posts = [x for x in post_latencies if x >= 900]

    sql_error_hits = 0
    db_signatures = set()
    for e in auth_posts:
        blob = " ".join([
            str(e.get("response_body_preview") or ""),
            str(e.get("error") or ""),
            str(e.get("content_type") or ""),
            str(e.get("response_server") or ""),
            str(e.get("response_powered_by") or ""),
        ]).lower()
        if any(token in blob for token in SQL_ERROR_PATTERNS):
            sql_error_hits += 1
        db_signatures.update(_detect_db_signatures(blob))

    confidence = 0.0
    if auth_posts:
        confidence += 0.30
    if post_median >= 400:
        confidence += 0.20
    if get_median and post_median >= int(get_median * 1.4):
        confidence += 0.15
    if slow_posts:
        confidence += 0.10
    if sql_error_hits:
        confidence += 0.25
    if db_signatures:
        confidence += 0.20
    confidence = min(0.99, round(confidence, 2))

    if confidence >= 0.7:
        status = "Detectado"
    elif confidence >= 0.4:
        status = "Indeterminado"
    else:
        status = "No evidenciado"

    return {
        "status": status,
        "confidence": confidence,
        "auth_posts": len(auth_posts),
        "all_posts": len(all_posts),
        "post_median_ms": post_median,
        "get_median_ms": get_median,
        "slow_posts": len(slow_posts),
        "sql_error_hits": sql_error_hits,
        "db_signatures": sorted(db_signatures),
    }


def build_login_db_intel_rows(*, raw_events, verified_events):
    analysis = infer_login_database_interaction(raw_events)
    signatures = ", ".join(analysis.get("db_signatures") or []) or "ninguna"

    rows = [{
        "control": "Interacción login-BBDD (inferencia por tráfico)",
        "status": analysis["status"],
        "severity": "Media" if analysis["status"] == "Detectado" else "Informativa",
        "description": "Se infiere interacción con backend/BBDD durante autenticación usando telemetría HTTP observable.",
        "evidence": (
            f"POST auth-like: {analysis['auth_posts']} | POST totales: {analysis['all_posts']} | "
            f"Mediana POST auth: {analysis['post_median_ms']} ms | Mediana GET: {analysis['get_median_ms']} ms | "
            f"POST lentos (>=900ms): {analysis['slow_posts']} | Errores SQL: {analysis['sql_error_hits']} | "
            f"Firmas BBDD: {signatures} | Confianza: {analysis['confidence']}"
        ),
        "recommendation": "Correlacionar con logs de aplicación/BBDD para confirmar consultas reales durante login y revisar hardening de errores SQL.",
    }]

    if verified_events:
        sample_posts = [e for e in (verified_events or []) if str(e.get("method") or "").upper() == "POST"][:6]
        if sample_posts:
            rows.append({
                "control": "Endpoints POST autenticados (candidatos a flujo con BBDD)",
                "status": "Comprobado",
                "severity": "Informativa",
                "description": "Endpoints POST observados en sesión autenticada para análisis de capa de datos.",
                "evidence": " | ".join([
                    f"{str(e.get('url') or '')} [HTTP {int(e.get('status_code') or 0)} | {int(e.get('duration_ms') or 0)} ms]"
                    for e in sample_posts
                ]) or "Sin endpoints POST verificables",
                "recommendation": "Priorizar estos endpoints en pruebas de SQLi controladas y monitoreo de consultas en backend autorizado.",
            })

    return rows


def build_kali_procedure_rows(*, target_url, has_auth, verified_events, db_assets):
    parsed = urlparse(str(target_url or ""))
    host = str(parsed.hostname or "")
    port_hint = str(parsed.port or (443 if parsed.scheme == "https" else 80))

    post_targets = [
        str(e.get("url") or "")
        for e in (verified_events or [])
        if str(e.get("method") or "").upper() == "POST"
    ]
    post_targets = list(dict.fromkeys([x for x in post_targets if x]))[:5]

    db_ports = sorted({int(a.get("port") or 0) for a in (db_assets or []) if int(a.get("port") or 0) > 0})
    db_port_text = ",".join(str(p) for p in db_ports[:8]) or "3306,5432,1433,1521,27017"

    base_cmds = [
        f"whatweb -a 3 {target_url}",
        f"wafw00f {target_url} -a",
        f"nmap -sV -sC -Pn --open -p {port_hint} {host}",
        f"nmap -sV -Pn --open -p {db_port_text} {host}",
    ]

    if has_auth and post_targets:
        first_post = post_targets[0]
        base_cmds.append(
            f"sqlmap -u \"{first_post}\" --method POST --batch --risk=1 --level=1 --random-agent"
        )

    return [{
        "control": "Procedimiento Kali recomendado (automatizable)",
        "status": "Comprobado",
        "severity": "Informativa",
        "description": "Runbook técnico para exprimir reconocimiento y validación controlada en entorno autorizado.",
        "evidence": " | ".join(base_cmds[:5]),
        "recommendation": "Ejecutar en ventana controlada y correlacionar con logs del servidor para evitar falsos positivos.",
    }]


def run_kali_quick_fingerprint(target_url):
    rows = []
    tools = {
        "whatweb": resolve_binary("whatweb", explicit_candidates=[r"C:\\tools\\whatweb\\whatweb.bat"]),
        "wafw00f": resolve_binary("wafw00f", explicit_candidates=[r"C:\\tools\\wafw00f\\wafw00f.py"]),
    }

    available = [name for name, item in tools.items() if item[0]]
    rows.append({
        "control": "Herramientas Kali detectadas",
        "status": "Detectado" if available else "No evidenciado",
        "severity": "Informativa",
        "description": "Detección local de herramientas de fingerprinting estilo Kali para enriquecer evidencias.",
        "evidence": f"Disponibles: {', '.join(available) if available else 'ninguna'}",
        "recommendation": "Instalar whatweb/wafw00f si se desea mayor cobertura de fingerprint externo.",
    })

    whatweb_bin = tools["whatweb"][0]
    if whatweb_bin:
        result = _run_command([whatweb_bin, "-a", "3", str(target_url or "")], timeout=25)
        out = (result.get("stdout") or "")[:260]
        rows.append({
            "control": "Kali quick fingerprint - WhatWeb",
            "status": "Comprobado" if result.get("ok") else "Error",
            "severity": "Informativa",
            "description": "Fingerprint tecnológico rápido para detectar stack y componentes visibles.",
            "evidence": out or (result.get("stderr") or "sin salida"),
            "recommendation": "Cruzar fingerprint con CVEs y versiones detectadas para priorizar validaciones.",
        })

    wafw00f_bin = tools["wafw00f"][0]
    if wafw00f_bin:
        result = _run_command([wafw00f_bin, str(target_url or ""), "-a"], timeout=30)
        combined = f"{result.get('stdout') or ''}\n{result.get('stderr') or ''}".strip()
        waf_summary = ""
        for line in combined.splitlines():
            line_low = line.lower()
            if "behind" in line_low or "waf" in line_low or "firewall" in line_low:
                waf_summary = line.strip()
                break
        rows.append({
            "control": "Kali quick fingerprint - WAF",
            "status": "Comprobado" if result.get("ok") else "No probado",
            "severity": "Informativa",
            "description": "Identificación rápida de presencia de WAF o capa de protección perimetral.",
            "evidence": (waf_summary or combined[:240] or "sin evidencia")[:260],
            "recommendation": "Si hay WAF, adaptar payloads y ritmo de pruebas para minimizar bloqueo y ruido.",
        })

    return rows
