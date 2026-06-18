# Modulo de configuracion global con constantes y perfiles de ejecucion de la herramienta.

import os
import importlib


def _is_truthy_env(value):
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _load_dotenv(dotenv_path=".env"):
    # python-dotenv supports disabling file loading via this env var.
    if _is_truthy_env(os.getenv("PYTHON_DOTENV_DISABLED")):
        return

    try:
        dotenv_mod = importlib.import_module("dotenv")
        find_dotenv = getattr(dotenv_mod, "find_dotenv")
        load_dotenv = getattr(dotenv_mod, "load_dotenv")
        # Resolve nearest .env from cwd upwards.
        resolved = find_dotenv(filename=dotenv_path, usecwd=True) or dotenv_path
        # Keep existing process/system variables as priority.
        load_dotenv(dotenv_path=resolved, override=False)
        return
    except Exception:
        pass

    if not os.path.exists(dotenv_path):
        return

    # Minimal fallback parser to keep startup resilient when dotenv is unavailable.
    # Supports only simple KEY=VALUE entries.
    try:
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = str(raw_line or "").strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = str(key or "").strip()
                value = str(value or "").strip()
                if not key:
                    continue
                if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                os.environ.setdefault(key, value)
    except Exception:
        pass


_load_dotenv()

APP_NAME = "BlackHarrier Web Sentinel"
APP_SUBTITLE = "Offensive Web Audit Platform by Jose"

SCAN_MODES = {
    "Quick": {
        "max_payloads": 3,
        "delay": 0.55,
        "aggressive": False,
        "port_scan_profile": "common",
        "vuln_correlation_profile": "basic",
        "nmap_profile": "SAFE",
        "nmap_udp": False,
        "nessus_poll_seconds": 90,
    },
    "Full": {
        "max_payloads": 10,
        "delay": 0.22,
        "aggressive": True,
        "port_scan_profile": "extended",
        "vuln_correlation_profile": "standard",
        "nmap_profile": "DEEP",
        "nmap_udp": False,
        "nessus_poll_seconds": 180,
    },
    "Infrastructure Deep Scan": {
        "max_payloads": 15,
        "delay": 0.1,
        "aggressive": True,
        "port_scan_profile": "deep",
        "vuln_correlation_profile": "deep",
        "nmap_profile": "KALI_FULL",
        "nmap_udp": True,
        "nessus_poll_seconds": 300,
    },
    "Safe": {
        "max_payloads": 3,
        "delay": 0.5,
        "aggressive": False,
        "port_scan_profile": "common",
        "vuln_correlation_profile": "basic",
        "nmap_profile": "SAFE",
        "nmap_udp": False,
        "nessus_poll_seconds": 90,
    },
    "Deep Audit": {
        "max_payloads": 8,
        "delay": 0.25,
        "aggressive": True,
        "port_scan_profile": "extended",
        "vuln_correlation_profile": "standard",
        "nmap_profile": "DEEP",
        "nmap_udp": False,
        "nessus_poll_seconds": 180,
    },
    "Offensive Authorized": {
        "max_payloads": 15,
        "delay": 0.1,
        "aggressive": True,
        "port_scan_profile": "deep",
        "vuln_correlation_profile": "deep",
        "nmap_profile": "KALI_FULL",
        "nmap_udp": True,
        "nessus_poll_seconds": 300,
    }
}
