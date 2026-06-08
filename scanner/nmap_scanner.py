# Modulo de ejecucion y normalizacion de reconocimiento de red basado en Nmap.

import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path


NMAP_PROFILES = {

    "SAFE": ["-sV", "-Pn", "-T4", "--open", "--reason", "--version-light"],


    "DEEP": ["-sV", "-sC", "-Pn", "-T4", "--open", "--reason", "--version-all"],

    "AGGRESSIVE": ["-sV", "-sC", "-Pn", "-T4", "--open", "--reason", "--version-all"],

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



    for fallback in _NMAP_FALLBACK_PATHS:
        if Path(fallback).exists():
            return fallback

    raise FileNotFoundError("No se encontró nmap.exe en PATH. Instalar Nmap para habilitar este módulo.")


def _emit(progress_callback, **kwargs):
    if progress_callback:
        try:
            progress_callback(kwargs)
        except Exception:


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


def _startupinfo_hidden():
    if os.name != "nt":
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0
    return info


def _detect_nmap_version(nmap_bin: str) -> str:
    try:
        proc = subprocess.run(
            [nmap_bin, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
            startupinfo=_startupinfo_hidden(),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        raw = str(proc.stdout or proc.stderr or "").strip()
        first = raw.splitlines()[0].strip() if raw else ""
        return first or "version_desconocida"
    except Exception:
        return "version_desconocida"


def _persist_nmap_artifacts(
    *,
    xml_path: str,
    scan_data: dict,
    profile_key: str,
    targets: list[str],
    nmap_bin: str,
    nmap_version: str,
    timed_out: bool = False,
) -> dict:
    runs_dir = Path("logs") / "nmap_runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = runs_dir / f"nmap_{profile_key.lower()}_{stamp}"

    xml_dump = str(base.with_suffix(".xml"))
    json_dump = str(base.with_suffix(".json"))

    try:
        shutil.copy2(xml_path, xml_dump)
    except Exception:
        xml_dump = ""

    payload = {
        "meta": {
            "timestamp": datetime.now().isoformat(),
            "profile": profile_key,
            "targets": list(targets or []),
            "nmap_binary": nmap_bin,
            "nmap_version": nmap_version,
            "timed_out": bool(timed_out),
            "hosts": len((scan_data or {}).get("hosts") or []),
        },
        "scan_data": scan_data or {"hosts": []},
    }
    try:
        with open(json_dump, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    except Exception:
        json_dump = ""

    return {"xml": xml_dump, "json": json_dump}


def _run_nmap_command(cmd: list[str], timeout_seconds: int, cancel_event=None, progress_callback=None) -> tuple[int, str, str]:
    """Run nmap safely with timeout/cancellation support."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        startupinfo=_startupinfo_hidden(),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
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

    _CRITICAL = {
        2375, 2376,
        5000,
        9000, 9001,
        3389,
        5900, 5901,
        6379,
        9200, 9300,
        27017, 27018,
        5985, 5986,
        2181,
        7001, 7002,
        1521,
        523,
    }

    _HIGH = {
        21,
        23,
        25,
        110, 143,
        139, 445,
        1433,
        3306,
        5432,
        8080, 8443,
        8000, 8001,
        8888,
        9100, 9101,
        9003,
        1883, 8883,
        3000,
        4848,
        4444,
    }

    _MEDIUM = {
        22,
        53,
        111, 135,
        389, 636,
        587, 465,
        993, 995,
        5601,
        15672,
        2049,
        161, 162,
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



    elevated = _is_elevated()
    if profile_key in ("DEEP", "AGGRESSIVE") and elevated:
        if "-O" not in args:
            args.append("-O")
    elif profile_key == "AGGRESSIVE" and "-A" in args and not elevated:

        args = [a for a in args if a != "-A"]
        for flag in ("-sV", "-sC"):
            if flag not in args:
                args.append(flag)

    if include_udp and "-sU" not in args:
        args.append("-sU")

    nmap_bin = _find_nmap_binary(nmap_path)
    nmap_version = _detect_nmap_version(nmap_bin)



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
        meta_row = {
            "control": "Nmap detectado y preparado",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "El binario de Nmap fue detectado y se ejecuta mediante subprocess en segundo plano (sin ventana visible en Windows).",
            "evidence": (
                f"Binario: {nmap_bin} | Versión: {nmap_version} | "
                f"Perfil: {profile_key} | Targets: {len(clean_targets)}"
            ),
            "recommendation": "Mantener Nmap actualizado y usar perfil KALI_FULL/DEEP para cobertura extensa en infraestructura autorizada.",
        }
        rc, _stdout, stderr = _run_nmap_command(
            cmd,
            timeout_seconds=effective_timeout,
            cancel_event=cancel_event,
            progress_callback=progress_callback,
        )

        if rc == 130:
            return ([meta_row, {
                "control": "Nmap reconnaissance",
                "status": "Error",
                "severity": "Media",
                "description": "Escaneo Nmap cancelado por el usuario/agente.",
                "evidence": "Cancel event recibido.",
                "recommendation": "Reintentar cuando la ventana de escaneo esté disponible.",
            }], {"hosts": []})

        if rc == 124:
            if Path(xml_path).exists():

                try:
                    scan_data = _parse_nmap_xml(xml_path, progress_callback=progress_callback)
                    rows = [meta_row]
                    rows.extend(normalize_nmap_results(scan_data, profile=profile_key))
                    dumps = _persist_nmap_artifacts(
                        xml_path=xml_path,
                        scan_data=scan_data,
                        profile_key=profile_key,
                        targets=clean_targets,
                        nmap_bin=nmap_bin,
                        nmap_version=nmap_version,
                        timed_out=True,
                    )
                    rows.append({
                        "control": "Nmap volcado de resultados",
                        "status": "Detectado",
                        "severity": "Informativa",
                        "description": "Se guardaron artefactos estructurados de Nmap para análisis posterior y trazabilidad.",
                        "evidence": f"XML: {dumps.get('xml') or 'no generado'} | JSON: {dumps.get('json') or 'no generado'}",
                        "recommendation": "Conservar estos artefactos para correlación, auditoría y comparación histórica.",
                    })
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

            return ([meta_row, {
                "control": "Nmap reconnaissance (sin resultados por timeout)",
                "status": "No probado",
                "severity": "Media",
                "description": "Timeout de Nmap alcanzado antes de finalizar. No hay datos suficientes para evaluar exposición de red.",
                "evidence": f"Timeout efectivo: {effective_timeout}s | Targets: {len(clean_targets)}",
                "recommendation": "Aumentar timeout o reducir alcance por ejecución. No tratar esta salida como ausencia de vulnerabilidades.",
            }], {"hosts": []})

        if not Path(xml_path).exists():
            return ([meta_row, {
                "control": "Nmap reconnaissance",
                "status": "Error",
                "severity": "Media",
                "description": "Nmap no generó salida XML estructurada.",
                "evidence": stderr[:500],
                "recommendation": "Verificar instalación de Nmap y permisos de ejecución.",
            }], {"hosts": []})

        scan_data = _parse_nmap_xml(xml_path, progress_callback=progress_callback)
        rows = [meta_row]
        rows.extend(normalize_nmap_results(scan_data, profile=profile_key))
        dumps = _persist_nmap_artifacts(
            xml_path=xml_path,
            scan_data=scan_data,
            profile_key=profile_key,
            targets=clean_targets,
            nmap_bin=nmap_bin,
            nmap_version=nmap_version,
            timed_out=False,
        )
        rows.append({
            "control": "Nmap volcado de resultados",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Se guardaron artefactos estructurados de Nmap para análisis posterior y trazabilidad.",
            "evidence": f"XML: {dumps.get('xml') or 'no generado'} | JSON: {dumps.get('json') or 'no generado'}",
            "recommendation": "Conservar estos artefactos para correlación, auditoría y comparación histórica.",
        })
        _emit(progress_callback, stage="nmap-finished", detail=f"Hosts: {len(scan_data.get('hosts', []))}")
        return rows, scan_data
