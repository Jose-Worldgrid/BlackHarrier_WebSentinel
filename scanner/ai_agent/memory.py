import json
import os
from datetime import datetime


MEMORY_PATH = "storage/ai_agent_memory.json"


def load_memory():
    if not os.path.exists(MEMORY_PATH):
        return {
            "patterns": [],
            "successful_selectors": [],
            "failed_selectors": [],
            "endpoint_patterns": [],
        }

    try:
        with open(MEMORY_PATH, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return {
            "patterns": [],
            "successful_selectors": [],
            "failed_selectors": [],
            "endpoint_patterns": [],
        }


def save_memory(memory):
    os.makedirs(os.path.dirname(MEMORY_PATH), exist_ok=True)

    with open(MEMORY_PATH, "w", encoding="utf-8") as file:
        json.dump(memory, file, ensure_ascii=False, indent=2)


def remember_pattern(pattern_type, data):
    memory = load_memory()

    memory.setdefault("patterns", []).append({
        "type": pattern_type,
        "data": data,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    })

    save_memory(memory)


def remember_successful_selector(url, selector_type, selector):
    memory = load_memory()

    memory.setdefault("successful_selectors", []).append({
        "url": url,
        "selector_type": selector_type,
        "selector": selector,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    })

    save_memory(memory)


def remember_endpoint_pattern(url, endpoint):
    memory = load_memory()

    memory.setdefault("endpoint_patterns", []).append({
        "url": url,
        "endpoint": endpoint,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    })

    save_memory(memory)