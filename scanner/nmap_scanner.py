import ctypes
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


NMAP_PROFILES = {
    # SAFE: version detection only, no ping, works without admin privileges
    "SAFE": ["-sV", "-Pn", "-T4", "--open", "--reason", "--version-light"],
    # DEEP: service + default scripts, T4 speed. -O requires raw sockets (admin
    # on Windows); injected at runtime only when the process is elevated.
    "DEEP": ["-sV", "-sC", "-Pn", "-T4", "--open", "--reason", "--version-all"],
    # AGGRESSIVE: broad offensive recon with curated NSE scripts.
    "AGGRESSIVE": ["-sV", "-sC", "-Pn", "-T4", "--open", "--reason", "--version-all"],
    # KALI_FULL: deep host/service/app/db/user enumeration inspired by common Kali playbooks.
    "KALI_FULL": ["-sV", "-sC", "-Pn", "-T4", "--open", "--reason", "--version-all", "--script-timeout", "20s"],
}


NMAP_PROFILE_SCRIPTS = {
    "DEEP": [
        "default", "safe", "discovery",
        "http-title", "http-server-header", "http-headers", "ssl-cert",
        "dns-nsid", "banner",
        "mysql-info", "mysql-variables", "mysql-databases",
        "ms-sql-info", "ms-sql-config",
        "pgsql-info", "mongodb-info", "redis-info",
    ],
    "AGGRESSIVE": [
        "default", "safe", "discovery", "vuln", "banner",
        "http-enum", "http-title", "http-server-header", "http-headers", "http-generator",
        "http-wordpress-enum", "http-drupal-enum-users",
        "ssl-cert", "ssl-enum-ciphers",
        "ftp-anon", "smtp-enum-users", "pop3-capabilities", "imap-capabilities",
        "ldap-rootdse", "smb-os-discovery", "smb-enum-users",
        "mysql-info", "mysql-variables", "mysql-databases",
        "ms-sql-info", "ms-sql-config",
        "pgsql-info", "mongodb-info", "redis-info",
    ],
    "KALI_FULL": [
        "default", "safe", "discovery", "vuln", "banner", "auth",
        "http-enum", "http-title", "http-server-header", "http-headers", "http-generator",
        "http-wordpress-enum", "http-drupal-enum-users", "http-userdir-enum",
        "ssl-cert", "ssl-enum-ciphers",
        "ftp-anon", "ftp-syst",
        "smtp-enum-users", "smtp-commands", "pop3-capabilities", "imap-capabilities",
        "ldap-rootdse", "ldap-search",
        "smb-os-discovery", "smb-enum-users", "smb-enum-shares", "smb-security-mode",
        "mysql-info", "mysql-variables", "mysql-databases",
        "ms-sql-info", "ms-sql-config", "ms-sql-empty-password",
        "pgsql-info", "mongodb-info", "redis-info",
        "snmp-info", "snmp-sysdescr", "dns-nsid",
    ],
}


DB_SERVICE_HINTS = {
    "mysql": "MySQL/MariaDB",
    "mariadb": "MySQL/MariaDB",
    "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL",
    "ms-sql": "Microsoft SQL Server",
    "mssql": "Microsoft SQL Server",
    "oracle": "Oracle Database",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "cassandra": "Cassandra",
    "couchdb": "CouchDB",
    "memcached": "Memcached",
}


TECH_SIGNATURES = {
    "WordPress": [r"wordpress"],
    "Drupal": [r"drupal"],
    "Joomla": [r"joomla"],
    "PHP": [r"\bphp/?\s*\d"],
    "ASP.NET": [r"asp\.net", r"x-aspnet"],
    "Node.js": [r"node\.js", r"express"],
    "Java/Spring": [r"spring", r"tomcat", r"jetty"],
    "Nginx": [r"nginx/?\s*\d"],
    "Apache": [r"apache/?\s*\d"],
    "IIS": [r"microsoft-iis"],
    "Next.js": [r"next\.js", r"x-powered-by:\s*next\.js"],
    "React": [r"react"],
    "Vue": [r"vue"],
    "Angular": [r"angular"],
}


USER_ENUM_SCRIPT_MARKERS = (
    "enum-users",
    "users",
    "userdir",
    "accounts",
)


def _is_elevated() -> bool:
    """True when the current process has admin/root privileges."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    try:
        import os as _os
        return _os.getuid() == 0
    except AttributeError:
        pass
    return False


@dataclass
class NmapProgress:
    stage: str
    host: str = ""
    port: str = ""
    service: str = ""
    version: str = ""
    nse: str = ""
    detail: str = ""


_NMAP_FALLBACK_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
]


def _find_nmap_binary(preferred_path: str | None = None) -> str:
    if preferred_path:
        candidate = Path(preferred_path)
        if candidate.exists():
            return str(candidate)

    for binary in ["nmap.exe", "nmap"]:
        found = shutil.which(binary)
        if found:
            return found

    # shutil.which misses Nmap when PATH wasn't refreshed after install –
    # fall back to known Windows install locations.
    for fallback in _NMAP_FALLBACK_PATHS:
        if Path(fallback).exists():
            return fallback

    raise FileNotFoundError("No se encontró nmap.exe en PATH. Instalar Nmap para habilitar este módulo.")


def _emit(progress_callback, **kwargs):
    if progress_callback:
        try:
            progress_callback(kwargs)
        except Exception:
            # Streamlit UI callbacks may run from non-main threads during process readers.
            # Never abort scan execution because of progress rendering errors.
            return


def _safe_kill(proc: subprocess.Popen | None):
    if not proc:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            time.sleep(0.2)
        if proc.poll() is None:
            proc.kill()
    except Exception:
        pass


def _run_nmap_command(cmd: list[str], timeout_seconds: int, cancel_event=None, progress_callback=None) -> tuple[int, str, str]:
    """Run nmap safely with timeout/cancellation support."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    stdout_chunks = []
    stderr_chunks = []

    def _reader(stream, sink, stream_name):
        while True:
            line = stream.readline()
            if not line:
                break
            sink.append(line)
            text = line.strip()
            if text:
                _emit(
                    progress_callback,
                    stage="nmap-runtime",
                    detail=text[:220],
                    stream=stream_name,
                )

    t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_chunks, "stdout"), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_chunks, "stderr"), daemon=True)
    t_out.start()
    t_err.start()

    start = time.time()
    while proc.poll() is None:
        if cancel_event and cancel_event.is_set():
            _safe_kill(proc)
            return 130, "", "cancelled"

        if timeout_seconds and (time.time() - start) > timeout_seconds:
            _safe_kill(proc)
            return 124, "", "timeout"

        time.sleep(0.15)

    t_out.join(timeout=0.6)
    t_err.join(timeout=0.6)

    return proc.returncode or 0, "".join(stdout_chunks), "".join(stderr_chunks)


def _parse_nmap_xml(xml_path: str, progress_callback=None) -> dict:
    root = ET.parse(xml_path).getroot()
    hosts_data = []

    for host_node in root.findall("host"):
        state_node = host_node.find("status")
        state = state_node.get("state", "unknown") if state_node is not None else "unknown"

        host_addrs = [addr.get("addr") for addr in host_node.findall("address") if addr.get("addr")]
        host_value = host_addrs[0] if host_addrs else "unknown"

        host_info = {
            "host": host_value,
            "state": state,
            "os": "",
            "ports": [],
            "scripts": [],
        }

        osmatch = host_node.find("os/osmatch")
        if osmatch is not None:
            host_info["os"] = osmatch.get("name", "")

        ports_node = host_node.find("ports")
        if ports_node is not None:
            for p in ports_node.findall("port"):
                state_el = p.find("state")
                service_el = p.find("service")
                if state_el is None:
                    continue

                port_data = {
                    "port": int(p.get("portid", "0") or "0"),
                    "protocol": p.get("protocol", "tcp"),
                    "state": state_el.get("state", "unknown"),
                    "service": service_el.get("name", "") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                    "extrainfo": service_el.get("extrainfo", "") if service_el is not None else "",
                    "ostype": service_el.get("ostype", "") if service_el is not None else "",
                    "method": service_el.get("method", "") if service_el is not None else "",
                    "conf": service_el.get("conf", "") if service_el is not None else "",
                    "cpes": [c.text for c in (service_el.findall("cpe") if service_el is not None else []) if c is not None and c.text],
                    "scripts": [],
                }

                for script in p.findall("script"):
                    sid = script.get("id", "")
                    out = script.get("output", "")
                    port_data["scripts"].append({"id": sid, "output": out})
                    if sid or out:
                        _emit(
                            progress_callback,
                            stage="nmap-nse",
                            host=host_value,
                            port=f"{port_data['port']}/{port_data['protocol']}",
                            service=port_data.get("service", ""),
                            version=port_data.get("version", ""),
                            nse=sid,
                            detail=out[:140],
                        )

                host_info["ports"].append(port_data)
                _emit(
                    progress_callback,
                    stage="nmap-port",
                    host=host_value,
                    port=f"{port_data['port']}/{port_data['protocol']}",
                    service=port_data.get("service", ""),
                    version=port_data.get("version", ""),
                )

        for script in host_node.findall("hostscript/script"):
            host_info["scripts"].append({
                "id": script.get("id", ""),
                "output": script.get("output", ""),
            })

        hosts_data.append(host_info)

    return {
        "hosts": hosts_data,
    }


def _severity_for_port(port: int) -> str:
    # ── Critical: direct full-system or unauthenticated access risk ─────
    _CRITICAL = {
        2375, 2376,         # Docker daemon (unauthenticated API)
        5000,               # Docker Registry (unauthenticated push/pull)
        9000, 9001,         # Portainer / SonarQube / Jenkins
        3389,               # RDP
        5900, 5901,         # VNC
        6379,               # Redis (unauthenticated)
        9200, 9300,         # Elasticsearch
        27017, 27018,       # MongoDB
        5985, 5986,         # WinRM
        2181,               # ZooKeeper
        7001, 7002,         # WebLogic
        1521,               # Oracle DB
        523,                # IBM DB2
    }
    # ── High: sensitive/management services ─────────────────────────────
    _HIGH = {
        21,                 # FTP (plaintext)
        23,                 # Telnet
        25,                 # SMTP (relay risk)
        110, 143,           # POP3 / IMAP (plaintext)
        139, 445,           # SMB
        1433,               # MSSQL
        3306,               # MySQL/MariaDB
        5432,               # PostgreSQL
        8080, 8443,         # Common admin/dev HTTP
        8000, 8001,         # Dev servers (Uvicorn/Gunicorn)
        8888,               # Jupyter Notebook
        9100, 9101,         # Prometheus node-exporter / JetDirect print
        9003,               # Often API/debug port
        1883, 8883,         # MQTT (IoT broker)
        3000,               # Node.js / Grafana / Gitea
        4848,               # GlassFish admin
        4444,               # Metasploit default listener
    }
    # ── Medium: infrastructure services needing review ──────────────────
    _MEDIUM = {
        22,                 # SSH
        53,                 # DNS
        111, 135,           # RPC
        389, 636,           # LDAP / LDAPS
        587, 465,           # SMTP submission
        993, 995,           # IMAP/POP3 SSL
        5601,               # Kibana
        15672,              # RabbitMQ management
        2049,               # NFS
        161, 162,           # SNMP
    }
    if port in _CRITICAL:
        return "Crítica"
    if port in _HIGH:
        return "Alta"
    if port in _MEDIUM:
        return "Media"
    return "Baja"


def _join_non_empty(parts: list[str], sep: str = " ") -> str:
    return sep.join([str(x).strip() for x in parts if str(x).strip()])


def _extract_tech_from_blob(blob: str) -> list[str]:
    low = str(blob or "").lower()
    found = []
    for name, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, low, re.IGNORECASE):
                found.append(name)
                break
    return sorted(set(found))


def _extract_user_candidates(text: str, max_items: int = 12) -> list[str]:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    users = []
    seen = set()

    patterns = [
        re.compile(r"(?:user(?:name)?|account)\s*[:=]\s*([A-Za-z0-9._@\-]{2,64})", re.IGNORECASE),
        re.compile(r"\b([A-Za-z0-9._-]{2,32})\b"),
    ]

    deny = {
        "open", "closed", "filtered", "http", "https", "smtp", "imap", "pop3",
        "admin", "root", "guest", "anonymous", "default", "users", "user",
        "success", "failed", "error", "warning", "service", "script",
    }

    for line in lines:
        if not any(marker in line.lower() for marker in ["user", "account", "login", "valid", "invalid"]):
            continue
        for regex in patterns:
            for match in regex.findall(line):
                token = str(match).strip(" ,;|[](){}<>\"'").lower()
                if not token or token in deny:
                    continue
                if len(token) < 3 or token.isdigit():
                    continue
                if token not in seen:
                    seen.add(token)
                    users.append(token)
                    if len(users) >= max_items:
                        return users

    return users


def _service_db_label(service: str, product: str, cpes: list[str]) -> str:
    blob = " ".join([service or "", product or "", " ".join(cpes or [])]).lower()
    for hint, label in DB_SERVICE_HINTS.items():
        if hint in blob:
            return label
    return ""


def normalize_nmap_results(scan_data: dict, profile: str) -> list[dict]:
    rows = []
    hosts = scan_data.get("hosts", [])

    if not hosts:
        return [{
            "control": "Nmap reconnaissance",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "Nmap no devolvió hosts activos en el alcance evaluado.",
            "evidence": f"Perfil: {profile}",
            "recommendation": "Validar objetivo/ruteo y permisos de red para escaneo autorizado.",
        }]

    open_ports_count = 0
    tech_seen = set()
    db_seen = set()
    user_enum_seen = set()

    for host in hosts:
        host_ip = host.get("host", "unknown")
        open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
        open_ports_count += len(open_ports)

        rows.append({
            "control": f"Nmap host discovery: {host_ip}",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Host identificado por Nmap dentro del alcance autorizado.",
            "evidence": (
                f"Host: {host_ip} | Estado: {host.get('state','')} | "
                f"SO estimado: {host.get('os','desconocido')} | "
                f"Puertos abiertos: {len(open_ports)}"
            ),
            "recommendation": "Mantener inventario de activos y segmentación por nivel de exposición.",
        })

        for p in open_ports:
            sev = _severity_for_port(int(p.get("port", 0) or 0))
            scripts = p.get("scripts") or []
            script_text = " ; ".join(
                f"{x.get('id','')}: {str(x.get('output',''))[:90]}" for x in scripts[:3]
            )
            cpes = p.get("cpes") or []
            cpe_text = ", ".join(cpes[:2])
            service_full = _join_non_empty([p.get("service", ""), p.get("product", ""), p.get("version", "")])
            tech_blob = "\n".join([
                service_full,
                p.get("extrainfo", ""),
                cpe_text,
                "\n".join(str(x.get("output", "")) for x in scripts[:6]),
            ])
            tech_hits = _extract_tech_from_blob(tech_blob)

            rows.append({
                "control": f"Nmap servicio expuesto {host_ip}:{p.get('port')}/{p.get('protocol')}",
                "status": "Posible hallazgo" if sev in {"Alta", "Media"} else "Detectado",
                "severity": sev,
                "description": (
                    f"Servicio detectado: {p.get('service','desconocido')} "
                    f"{p.get('product','')} {p.get('version','')}"
                ).strip(),
                "evidence": (
                    f"Host: {host_ip} | Puerto: {p.get('port')}/{p.get('protocol')} | "
                    f"Servicio: {p.get('service','')} | Producto: {p.get('product','')} | "
                    f"Versión: {p.get('version','')}"
                    + (f" | CPE: {cpe_text}" if cpe_text else "")
                    + (f" | NSE: {script_text}" if script_text else "")
                ),
                "recommendation": "Restringir exposición a red pública, aplicar hardening y parches del servicio detectado.",
            })

            for tech in tech_hits:
                tech_key = (host_ip, int(p.get("port", 0) or 0), tech)
                if tech_key in tech_seen:
                    continue
                tech_seen.add(tech_key)
                rows.append({
                    "control": f"Fingerprint tecnológico (Nmap): {tech}",
                    "status": "Detectado",
                    "severity": "Informativa",
                    "description": "Nmap/NSE detectó indicadores de framework, lenguaje o stack aplicativa.",
                    "evidence": (
                        f"Host: {host_ip} | Puerto: {p.get('port')}/{p.get('protocol')} | "
                        f"Stack detectado: {tech} | Servicio: {service_full or 'n/a'}"
                    ),
                    "recommendation": "Correlacionar versión real con CVEs y validar exposición de componentes en Internet.",
                })

            db_label = _service_db_label(str(p.get("service", "")), str(p.get("product", "")), cpes)
            if db_label:
                db_key = (host_ip, int(p.get("port", 0) or 0), db_label)
                if db_key not in db_seen:
                    db_seen.add(db_key)
                    rows.append({
                        "control": f"Base de datos expuesta detectada: {db_label}",
                        "status": "Posible hallazgo",
                        "severity": "Alta" if int(p.get("port", 0) or 0) in {6379, 27017, 9200, 3306, 5432, 1433, 1521} else "Media",
                        "description": "Se detectó servicio de base de datos o motor de búsqueda accesible por red.",
                        "evidence": (
                            f"Host/IP: {host_ip} | Puerto: {p.get('port')}/{p.get('protocol')} | "
                            f"Tipo BBDD: {db_label} | Producto: {p.get('product','')} | Versión: {p.get('version','')}"
                            + (f" | CPE: {cpe_text}" if cpe_text else "")
                        ),
                        "recommendation": "Restringir acceso por ACL/VPN, forzar autenticación robusta y revisar cifrado en tránsito.",
                    })

            for script in scripts:
                sid = str(script.get("id", "") or "").lower()
                sout = str(script.get("output", "") or "")
                if not sid or not sout:
                    continue
                if not any(marker in sid for marker in USER_ENUM_SCRIPT_MARKERS):
                    continue
                users = _extract_user_candidates(sout)
                evidence_users = ", ".join(users[:8]) if users else "sin usuarios explícitos extraídos"
                enum_key = (host_ip, int(p.get("port", 0) or 0), sid, evidence_users)
                if enum_key in user_enum_seen:
                    continue
                user_enum_seen.add(enum_key)
                rows.append({
                    "control": f"Enumeración de usuarios (Nmap NSE): {sid}",
                    "status": "Posible hallazgo" if users else "Detectado",
                    "severity": "Media" if users else "Informativa",
                    "description": "Nmap NSE ejecutó script de enumeración de usuarios/cuentas en servicio remoto.",
                    "evidence": (
                        f"Host/IP: {host_ip} | Puerto: {p.get('port')}/{p.get('protocol')} | "
                        f"Script: {sid} | Usuarios candidatos: {evidence_users} | "
                        f"Salida: {sout[:220]}"
                    ),
                    "recommendation": "Unificar respuestas de autenticación, aplicar rate limit y bloquear enumeración por canal externo.",
                })

    rows.append({
        "control": "Nmap export estructurado",
        "status": "Detectado",
        "severity": "Informativa",
        "description": "Resultados de Nmap exportados a estructura JSON para correlación IA y reporting.",
        "evidence": json.dumps(
            {
                "profile": profile,
                "hosts": len(hosts),
                "open_ports": open_ports_count,
                "tech_fingerprints": len(tech_seen),
                "database_findings": len(db_seen),
                "user_enum_events": len(user_enum_seen),
            },
            ensure_ascii=False,
        ),
        "recommendation": "Usar esta salida estructurada para correlación de CVE y priorización ofensiva.",
    })

    return rows


def run_nmap_recon(
    targets: list[str],
    profile: str = "SAFE",
    nmap_path: str | None = None,
    timeout_seconds: int = 480,
    include_udp: bool = False,
    custom_scripts: str = "",
    progress_callback=None,
    cancel_event=None,
) -> tuple[list[dict], dict]:
    """Execute Nmap scan with XML parsing and normalized output."""
    clean_targets = [str(t).strip() for t in (targets or []) if str(t).strip()]
    if not clean_targets:
        return ([{
            "control": "Nmap reconnaissance",
            "status": "No probado",
            "severity": "Informativa",
            "description": "Sin objetivos para Nmap.",
            "evidence": "Lista de targets vacía.",
            "recommendation": "Verificar discovery/crawler para poblar hosts/IPs.",
        }], {"hosts": []})

    profile_key = str(profile or "SAFE").upper()
    args = list(NMAP_PROFILES.get(profile_key, NMAP_PROFILES["SAFE"]))

    script_items = []
    script_items.extend(NMAP_PROFILE_SCRIPTS.get(profile_key, []))
    if custom_scripts:
        script_items.extend([x.strip() for x in str(custom_scripts).split(",") if x.strip()])
    script_items = list(dict.fromkeys(script_items))
    if script_items:
        args.append(f"--script={','.join(script_items)}")

    # -O (OS detection) and -sS (SYN stealth) require raw packet privileges.
    # Inject -O only when elevated to avoid incomplete/degraded scans.
    elevated = _is_elevated()
    if profile_key in ("DEEP", "AGGRESSIVE") and elevated:
        if "-O" not in args:
            args.append("-O")
    elif profile_key == "AGGRESSIVE" and "-A" in args and not elevated:
        # -A implicitly includes -O. Without admin replace with explicit safe flags.
        args = [a for a in args if a != "-A"]
        for flag in ("-sV", "-sC"):
            if flag not in args:
                args.append(flag)

    if include_udp and "-sU" not in args:
        args.append("-sU")

    nmap_bin = _find_nmap_binary(nmap_path)

    # Adaptive timeout: when scanning several hosts or deeper profiles, 420s may
    # be too low and causes premature aborts with incomplete output.
    per_target_floor = 90
    if profile_key == "DEEP":
        per_target_floor = 150
    elif profile_key == "AGGRESSIVE":
        per_target_floor = 240
    effective_timeout = max(int(timeout_seconds or 0), len(clean_targets) * per_target_floor)

    with tempfile.TemporaryDirectory(prefix="bh_nmap_") as tmpdir:
        xml_path = str(Path(tmpdir) / "nmap_scan.xml")
        cmd = [
            nmap_bin,
            *args,
            "--stats-every",
            "5s",
            "-oX",
            xml_path,
            *clean_targets,
        ]

        _emit(progress_callback, stage="nmap-start", detail=" ".join(cmd))
        rc, _stdout, stderr = _run_nmap_command(
            cmd,
            timeout_seconds=effective_timeout,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
        )

        if rc == 130:
            return ([{
                "control": "Nmap reconnaissance",
                "status": "Error",
                "severity": "Media",
                "description": "Escaneo Nmap cancelado por el usuario/agente.",
                "evidence": "Cancel event recibido.",
                "recommendation": "Reintentar cuando la ventana de escaneo esté disponible.",
            }], {"hosts": []})

        if rc == 124:
            if Path(xml_path).exists():
                # Nmap usually writes partial XML; salvage data instead of discarding it.
                try:
                    scan_data = _parse_nmap_xml(xml_path, progress_callback=progress_callback)
                    rows = normalize_nmap_results(scan_data, profile=profile_key)
                    rows.append({
                        "control": "Nmap reconnaissance (cobertura incompleta)",
                        "status": "No probado",
                        "severity": "Media",
                        "description": "Timeout de Nmap alcanzado antes de finalizar. Se conserva resultado parcial sin inferir ausencia de riesgo.",
                        "evidence": (
                            f"Timeout efectivo: {effective_timeout}s | "
                            f"Targets solicitados: {len(clean_targets)} | "
                            f"Hosts parseados parcial: {len(scan_data.get('hosts', []))}"
                        ),
                        "recommendation": "Repetir Nmap por lotes más pequeños o con timeout mayor antes de cerrar dictamen de infraestructura.",
                    })
                    return rows, scan_data
                except Exception:
                    pass

            return ([{
                "control": "Nmap reconnaissance (sin resultados por timeout)",
                "status": "No probado",
                "severity": "Media",
                "description": "Timeout de Nmap alcanzado antes de finalizar. No hay datos suficientes para evaluar exposición de red.",
                "evidence": f"Timeout efectivo: {effective_timeout}s | Targets: {len(clean_targets)}",
                "recommendation": "Aumentar timeout o reducir alcance por ejecución. No tratar esta salida como ausencia de vulnerabilidades.",
            }], {"hosts": []})

        if not Path(xml_path).exists():
            return ([{
                "control": "Nmap reconnaissance",
                "status": "Error",
                "severity": "Media",
                "description": "Nmap no generó salida XML estructurada.",
                "evidence": stderr[:500],
                "recommendation": "Verificar instalación de Nmap y permisos de ejecución.",
            }], {"hosts": []})

        scan_data = _parse_nmap_xml(xml_path, progress_callback=progress_callback)
        rows = normalize_nmap_results(scan_data, profile=profile_key)
        _emit(progress_callback, stage="nmap-finished", detail=f"Hosts: {len(scan_data.get('hosts', []))}")
        return rows, scan_data
