import socket
import ssl
import time
from urllib.parse import urlparse


COMMON_PORTS = [
    21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9200, 27017,
]

EXTENDED_PORTS = COMMON_PORTS + [
    23, 81, 88, 389, 636, 989, 990, 1080, 2049, 2375, 5000, 5601,
    8000, 8008, 8081, 8888, 9090, 10000,
]

DEEP_PORTS = EXTENDED_PORTS + [
    26, 49, 113, 119, 161, 162, 465, 873, 1025, 1723, 1883, 2181,
    3128, 33060, 5985, 5986, 7001, 7002, 7777, 9201,
]

# Severity levels for exposed services
CRITICAL_PORTS = {
    23: "Telnet — protocolo sin cifrado, credenciales en claro.",
    3389: "RDP — acceso remoto de escritorio expuesto públicamente. Alto riesgo de fuerza bruta.",
    5900: "VNC — acceso remoto sin cifrado o autenticación débil.",
    6379: "Redis — tipicamente sin autenticación. Acceso directo a datos y ejecución RCE.",
    9200: "Elasticsearch — API REST expuesta. Fuga de datos sin autenticación.",
    27017: "MongoDB — base de datos expuesta sin autenticación por defecto.",
    2375: "Docker API — acceso sin TLS al daemon. RCE en el host.",
    5985: "WinRM (HTTP) — gestión remota Windows expuesta.",
    5986: "WinRM (HTTPS) — gestión remota Windows.",
}

HIGH_PORTS = {
    21: "FTP — transferencia sin cifrado. Riesgo de sniffing y credenciales expuestas.",
    25: "SMTP — relay abierto potencial. Riesgo de spam y enumeración de usuarios.",
    110: "POP3 sin cifrar — credenciales de correo en claro.",
    139: "NetBIOS — enumeración SMB y posibles ataques de relay NTLM.",
    445: "SMB/CIFS — objetivo de ransomware y ataques de relay (EternalBlue, etc.).",
    1433: "SQL Server — base de datos expuesta a internet.",
    1521: "Oracle DB — base de datos expuesta a internet.",
    3306: "MySQL — base de datos expuesta. Validar autenticación y bind address.",
    5432: "PostgreSQL — base de datos expuesta. Validar pg_hba.conf.",
    8080: "HTTP alternativo — puede exponer panel de administración o APIs sin TLS.",
    1883: "MQTT — broker IoT sin autenticación habitual.",
    2181: "ZooKeeper — coordinación distribuida sin autenticación por defecto.",
    7001: "WebLogic — servidor Java EE con historial de CVEs críticos.",
    7002: "WebLogic SSL.",
}

MEDIUM_PORTS = {
    22: "SSH — expuesto. Validar versión, cipher suites y protección brute-force.",
    53: "DNS — exposición de zona o recursivo abierto.",
    111: "RPCbind — enumeración de servicios RPC.",
    135: "MSRPC — endpoint mapper Windows.",
    143: "IMAP sin cifrar.",
    389: "LDAP — directorio activo expuesto sin TLS.",
    636: "LDAPS — LDAP sobre SSL.",
    587: "SMTP submission.",
    993: "IMAPS.",
    995: "POP3S.",
    5601: "Kibana — interfaz de logs potencialmente expuesta.",
    9090: "Prometheus/panel de admin.",
    10000: "Webmin — panel de administración.",
    33060: "MySQL X Protocol.",
}

RISKY_EXPOSED_PORTS = {**CRITICAL_PORTS, **HIGH_PORTS, **MEDIUM_PORTS}

PORT_SEVERITY = {}
for p in CRITICAL_PORTS:
    PORT_SEVERITY[p] = "Alta"
for p in HIGH_PORTS:
    PORT_SEVERITY[p] = "Alta"
for p in MEDIUM_PORTS:
    PORT_SEVERITY[p] = "Media"


def _target_host(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    return parsed.hostname or str(url or "").strip()


def _probe_port(host: str, port: int, timeout: float = 0.35):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = ""
            try:
                data = sock.recv(120)
                if data:
                    banner = data.decode("utf-8", errors="ignore").strip().replace("\n", " ")
            except Exception:
                banner = ""
            return True, banner[:120]
    except Exception:
        return False, ""


def _http_probe(host: str, port: int, timeout: float = 0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode("ascii", errors="ignore"))
            data = sock.recv(240).decode("utf-8", errors="ignore").replace("\n", " ").strip()
            return data[:180]
    except Exception:
        return ""


def _tls_probe(host: str, port: int, timeout: float = 0.8):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                subject = cert.get("subject", [])
                issuer = cert.get("issuer", [])
                tls_ver = tls_sock.version() or "unknown"
                subject_txt = ",".join(["=".join(item) for row in subject for item in row])[:90]
                issuer_txt = ",".join(["=".join(item) for row in issuer for item in row])[:90]
                return f"TLS:{tls_ver} | subject:{subject_txt or 'n/a'} | issuer:{issuer_txt or 'n/a'}"
    except Exception:
        return ""


def _redis_probe(host: str, port: int, timeout: float = 0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"INFO\r\n")
            data = sock.recv(180).decode("utf-8", errors="ignore").replace("\n", " ").strip()
            return data[:150]
    except Exception:
        return ""


def _ports_for_profile(profile: str):
    key = str(profile or "common").strip().lower()
    if key == "deep":
        return sorted(set(DEEP_PORTS))
    if key == "extended":
        return sorted(set(EXTENDED_PORTS))
    return sorted(set(COMMON_PORTS))


def scan_port_services(url: str, profile: str = "common"):
    """Service exposure scan inspired by Nmap top-ports. Authorized scope only."""
    host = _target_host(url)
    if not host:
        return [{
            "control": "Descubrimiento de puertos y servicios",
            "status": "Error",
            "severity": "Baja",
            "description": "No se pudo extraer el host objetivo para escaneo de puertos.",
            "evidence": f"URL/host recibido: {url}",
            "recommendation": "Indicar URL válida con dominio o IP.",
        }]

    open_ports = []
    banners = {}
    protocol_signals = []
    ports_to_scan = _ports_for_profile(profile)

    for port in ports_to_scan:
        is_open, banner = _probe_port(host, port)
        if not is_open:
            continue
        open_ports.append(port)
        if banner:
            banners[port] = banner

        # Protocol-aware probes for extra intelligence
        if port in (80, 8080, 8000, 8008, 8081, 8888, 9090, 10000):
            hint = _http_probe(host, port)
            if hint:
                protocol_signals.append(f"{port}/HTTP: {hint[:80]}")

        elif port in (443, 8443, 9443, 636):
            hint = _tls_probe(host, port)
            if hint:
                protocol_signals.append(f"{port}/TLS: {hint[:80]}")

        elif port == 6379:
            hint = _redis_probe(host, port)
            if hint:
                protocol_signals.append(f"{port}/Redis: {hint[:60]}")

    if not open_ports:
        return [{
            "control": "Descubrimiento de puertos y servicios",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": f"No se detectaron puertos abiertos en perfil '{profile}'.",
            "evidence": f"Host: {host} | Puertos evaluados: {len(ports_to_scan)}",
            "recommendation": "Complementar con inventario de red autorizado.",
        }]

    # Build banner evidence string
    banner_str = " ; ".join(f"{p}:{b}" for p, b in list(banners.items())[:6])
    signal_str = " ; ".join(protocol_signals[:5])

    results = [{
        "control": "Descubrimiento de puertos y servicios",
        "status": "Detectado",
        "severity": "Informativa",
        "description": (
            f"Se encontraron {len(open_ports)} puerto(s) abierto(s) "
            f"en perfil '{profile}'."
        ),
        "evidence": (
            f"Host: {host} | Perfil: {profile} | "
            f"Abiertos: {', '.join(str(p) for p in open_ports)}"
            + (f" | Banners: {banner_str}" if banner_str else "")
            + (f" | Protocolos: {signal_str}" if signal_str else "")
        ),
        "recommendation": (
            "Restringir puertos no necesarios al público mediante firewall. "
            "Validar cada servicio expuesto."
        ),
    }]

    # Report each critical/high/medium risky port individually for granularity
    critical_found = [p for p in open_ports if p in CRITICAL_PORTS]
    high_found = [p for p in open_ports if p in HIGH_PORTS and p not in CRITICAL_PORTS]
    medium_found = [p for p in open_ports if p in MEDIUM_PORTS]

    for port in critical_found:
        results.append({
            "control": f"Puerto crítico expuesto: {port}",
            "status": "Posible hallazgo",
            "severity": "Alta",
            "description": CRITICAL_PORTS[port],
            "evidence": (
                f"Host: {host} | Puerto: {port} | "
                + (f"Banner: {banners[port]}" if port in banners else "Sin banner")
            ),
            "recommendation": (
                "Cerrar o segmentar inmediatamente. Aplicar autenticación fuerte "
                "y cifrado si el servicio es necesario."
            ),
        })

    if high_found or medium_found:
        details = [
            f"{p}: {RISKY_EXPOSED_PORTS[p]}"
            for p in sorted(high_found + medium_found)
        ]
        results.append({
            "control": "Servicios con riesgo de exposición",
            "status": "Posible hallazgo",
            "severity": "Media" if not high_found else "Alta",
            "description": "Servicios expuestos que requieren hardening y restricción de acceso.",
            "evidence": " | ".join(details[:12]),
            "recommendation": (
                "Aplicar segmentación de red, autenticación MFA donde aplique "
                "y revisar permisos de acceso."
            ),
        })

    return results
