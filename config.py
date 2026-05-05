APP_NAME = "BlackHarrier Web Sentinel"
APP_SUBTITLE = "Offensive Web Audit Platform by Jose"

SCAN_MODES = {
    "Safe": {
        "max_payloads": 3,
        "delay": 0.5,
        "aggressive": False
    },
    "Deep Audit": {
        "max_payloads": 8,
        "delay": 0.25,
        "aggressive": True
    },
    "Offensive Authorized": {
        "max_payloads": 15,
        "delay": 0.1,
        "aggressive": True
    }
}