APP_NAME = "BlackHarrier Web Sentinel"
APP_SUBTITLE = "Offensive Web Audit Platform by Jose"

SCAN_MODES = {
    "Quick": {
        "max_payloads": 3,
        "delay": 0.55,
        "aggressive": False,
        "port_scan_profile": "common",
        "vuln_correlation_profile": "basic",
    },
    "Full": {
        "max_payloads": 10,
        "delay": 0.22,
        "aggressive": True,
        "port_scan_profile": "extended",
        "vuln_correlation_profile": "standard",
    },
    "Infrastructure Deep Scan": {
        "max_payloads": 15,
        "delay": 0.1,
        "aggressive": True,
        "port_scan_profile": "deep",
        "vuln_correlation_profile": "deep",
    },
    "Safe": {
        "max_payloads": 3,
        "delay": 0.5,
        "aggressive": False,
        "port_scan_profile": "common",
        "vuln_correlation_profile": "basic",
    },
    "Deep Audit": {
        "max_payloads": 8,
        "delay": 0.25,
        "aggressive": True,
        "port_scan_profile": "extended",
        "vuln_correlation_profile": "standard",
    },
    "Offensive Authorized": {
        "max_payloads": 15,
        "delay": 0.1,
        "aggressive": True,
        "port_scan_profile": "deep",
        "vuln_correlation_profile": "deep",
    }
}