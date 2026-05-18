import json
import shutil
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path


NMAP_PROFILES = {
    "SAFE": ["-sV", "-Pn", "-T3"],
    "DEEP": ["-sV", "-sC", "-O", "-Pn"],
    "AGGRESSIVE": ["-sV", "-sC", "-A", "-O", "-Pn", "--script=vuln,http-enum,http-title"],
}


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
        progress_callback(kwargs)


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
    if port in {23, 3389, 5900, 6379, 9200, 27017, 2375, 5985, 5986}:
        return "Alta"
    if port in {21, 25, 110, 139, 445, 1433, 1521, 3306, 5432, 8080, 1883, 2181, 7001, 7002}:
        return "Alta"
    if port in {22, 53, 111, 135, 143, 389, 636, 587, 993, 995}:
        return "Media"
    return "Baja"


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
                    + (f" | NSE: {script_text}" if script_text else "")
                ),
                "recommendation": "Restringir exposición a red pública, aplicar hardening y parches del servicio detectado.",
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

    if include_udp and "-sU" not in args:
        args.append("-sU")

    if custom_scripts:
        args.append(f"--script={custom_scripts}")

    nmap_bin = _find_nmap_binary(nmap_path)

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
            timeout_seconds=timeout_seconds,
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
            return ([{
                "control": "Nmap reconnaissance",
                "status": "Error",
                "severity": "Media",
                "description": "Timeout de Nmap alcanzado antes de finalizar.",
                "evidence": f"Timeout: {timeout_seconds}s",
                "recommendation": "Aumentar timeout o reducir alcance del escaneo.",
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
