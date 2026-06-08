# Modulo de configuracion global con constantes y perfiles de ejecucion de la herramienta.

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
