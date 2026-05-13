import json
import os
from datetime import datetime
from urllib.parse import urlparse


MEMORY_PATH = "storage/ai_agent_memory.json"
MAX_PATTERN_HISTORY = 500
MAX_SELECTOR_HISTORY = 500
MAX_ENDPOINT_HISTORY = 500
MAX_AUDIT_HISTORY = 120


def _now_iso():
    return datetime.now().isoformat(timespec="seconds")


def _default_memory():
    return {
        "meta": {
            "schema_version": 2,
            "updated_at": _now_iso(),
        },
        "patterns": [],
        "successful_selectors": [],
        "failed_selectors": [],
        "endpoint_patterns": [],
        "audit_history": [],
        "attack_stats": {},
        "page_type_stats": {},
        "endpoint_tokens": {},
    }


def _trim_list(memory, key, max_items):
    values = memory.get(key) or []
    if len(values) > max_items:
        memory[key] = values[-max_items:]


def _safe_lower(value):
    return str(value or "").strip().lower()


def _extract_host(value):
    parsed = urlparse(str(value or ""))
    return parsed.netloc.lower()


def _extract_path_tokens(endpoint):
    parsed = urlparse(str(endpoint or ""))
    path = parsed.path or str(endpoint or "")
    tokens = []
    for token in path.split("/"):
        cleaned = "".join(ch for ch in token.lower() if ch.isalnum() or ch in ["_", "-"])
        if len(cleaned) >= 3:
            tokens.append(cleaned)
    return tokens[:8]


def _migrate_memory(raw):
    memory = _default_memory()

    if not isinstance(raw, dict):
        return memory

    for key in [
        "patterns",
        "successful_selectors",
        "failed_selectors",
        "endpoint_patterns",
        "audit_history",
    ]:
        if isinstance(raw.get(key), list):
            memory[key] = raw[key]

    for key in ["attack_stats", "page_type_stats", "endpoint_tokens"]:
        if isinstance(raw.get(key), dict):
            memory[key] = raw[key]

    meta = raw.get("meta") or {}
    if isinstance(meta, dict):
        memory["meta"].update(meta)

    memory["meta"]["schema_version"] = 2
    memory["meta"]["updated_at"] = _now_iso()

    _trim_list(memory, "patterns", MAX_PATTERN_HISTORY)
    _trim_list(memory, "successful_selectors", MAX_SELECTOR_HISTORY)
    _trim_list(memory, "failed_selectors", MAX_SELECTOR_HISTORY)
    _trim_list(memory, "endpoint_patterns", MAX_ENDPOINT_HISTORY)
    _trim_list(memory, "audit_history", MAX_AUDIT_HISTORY)
    return memory


def load_memory():
    if not os.path.exists(MEMORY_PATH):
        return _default_memory()

    try:
        with open(MEMORY_PATH, "r", encoding="utf-8") as file:
            raw = json.load(file)
            return _migrate_memory(raw)
    except Exception:
        return _default_memory()


def save_memory(memory):
    os.makedirs(os.path.dirname(MEMORY_PATH), exist_ok=True)

    if not isinstance(memory, dict):
        memory = _default_memory()

    memory.setdefault("meta", {})
    memory["meta"]["schema_version"] = 2
    memory["meta"]["updated_at"] = _now_iso()

    with open(MEMORY_PATH, "w", encoding="utf-8") as file:
        json.dump(memory, file, ensure_ascii=False, indent=2)


def remember_pattern(pattern_type, data):
    memory = load_memory()

    memory.setdefault("patterns", []).append({
        "type": pattern_type,
        "data": data,
        "created_at": _now_iso(),
    })

    _trim_list(memory, "patterns", MAX_PATTERN_HISTORY)

    save_memory(memory)


def remember_successful_selector(url, selector_type, selector):
    memory = load_memory()

    memory.setdefault("successful_selectors", []).append({
        "url": url,
        "selector_type": selector_type,
        "selector": selector,
        "created_at": _now_iso(),
    })

    _trim_list(memory, "successful_selectors", MAX_SELECTOR_HISTORY)

    save_memory(memory)


def remember_failed_selector(url, selector_type, selector):
    memory = load_memory()

    memory.setdefault("failed_selectors", []).append({
        "url": url,
        "selector_type": selector_type,
        "selector": selector,
        "created_at": _now_iso(),
    })

    _trim_list(memory, "failed_selectors", MAX_SELECTOR_HISTORY)

    save_memory(memory)


def remember_endpoint_pattern(url, endpoint):
    memory = load_memory()
    host = _extract_host(url)

    memory.setdefault("endpoint_patterns", []).append({
        "url": url,
        "host": host,
        "endpoint": endpoint,
        "created_at": _now_iso(),
    })

    _trim_list(memory, "endpoint_patterns", MAX_ENDPOINT_HISTORY)

    tokens = memory.setdefault("endpoint_tokens", {})
    for token in _extract_path_tokens(endpoint):
        tokens[token] = int(tokens.get(token, 0)) + 1

    save_memory(memory)


def record_audit_feedback(target_url, pages, results):
    memory = load_memory()

    finding_statuses = {"hallazgo", "posible hallazgo"}
    error_statuses = {"error"}

    target_host = _extract_host(target_url)
    normalized_results = results or []

    findings = 0
    errors = 0
    modules_seen = set()

    attack_stats = memory.setdefault("attack_stats", {})

    for item in normalized_results:
        module = str(item.get("Módulo") or item.get("module") or "desconocido").strip() or "desconocido"
        status = _safe_lower(item.get("Resultado") or item.get("status"))

        modules_seen.add(module)

        module_stats = attack_stats.setdefault(module, {
            "attempts": 0,
            "findings": 0,
            "errors": 0,
            "last_status": "",
            "last_updated": "",
        })
        module_stats["attempts"] = int(module_stats.get("attempts", 0)) + 1

        if status in finding_statuses:
            module_stats["findings"] = int(module_stats.get("findings", 0)) + 1
            findings += 1
        elif status in error_statuses:
            module_stats["errors"] = int(module_stats.get("errors", 0)) + 1
            errors += 1

        module_stats["last_status"] = status
        module_stats["last_updated"] = _now_iso()

    page_type_stats = memory.setdefault("page_type_stats", {})
    endpoint_hits = 0
    endpoint_patterns = memory.setdefault("endpoint_patterns", [])
    endpoint_tokens = memory.setdefault("endpoint_tokens", {})

    for page in pages or []:
        ai_context = page.get("ai_context") or {}
        page_type = _safe_lower(ai_context.get("page_type") or page.get("classification") or "unknown")
        entry = page_type_stats.setdefault(page_type, {
            "seen": 0,
            "audits_with_findings": 0,
            "last_seen": "",
        })
        entry["seen"] = int(entry.get("seen", 0)) + 1
        if findings > 0:
            entry["audits_with_findings"] = int(entry.get("audits_with_findings", 0)) + 1
        entry["last_seen"] = _now_iso()

        for endpoint in ai_context.get("candidate_endpoints") or []:
            endpoint_hits += 1
            endpoint_source = page.get("final_url") or page.get("url") or target_url
            endpoint_patterns.append({
                "url": endpoint_source,
                "host": _extract_host(endpoint_source),
                "endpoint": endpoint,
                "created_at": _now_iso(),
            })
            for token in _extract_path_tokens(endpoint):
                endpoint_tokens[token] = int(endpoint_tokens.get(token, 0)) + 1

    summary = {
        "target_url": target_url,
        "target_host": target_host,
        "pages": len(pages or []),
        "results": len(normalized_results),
        "findings": findings,
        "errors": errors,
        "modules": sorted(modules_seen),
        "endpoint_hits": endpoint_hits,
        "created_at": _now_iso(),
    }

    memory.setdefault("audit_history", []).append(summary)
    _trim_list(memory, "endpoint_patterns", MAX_ENDPOINT_HISTORY)
    _trim_list(memory, "audit_history", MAX_AUDIT_HISTORY)
    save_memory(memory)

    return summary