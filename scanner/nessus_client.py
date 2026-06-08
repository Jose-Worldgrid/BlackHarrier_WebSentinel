# Modulo de escaneo y analisis para nessus client.

import json
import time
from dataclasses import dataclass

import requests


SEV_MAP = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Informativa",
    "none": "Informativa",
}


@dataclass
class NessusConfig:
    mode: str = "nessus-local"
    base_url: str = "https://localhost:8834"
    access_key: str = ""
    secret_key: str = ""
    verify_ssl: bool = False
    poll_interval_seconds: int = 6
    max_poll_seconds: int = 240
    scan_name: str = "BlackHarrier External Scan"
    template_uuid: str = "basic"


class NessusClient:
    def __init__(self, cfg: NessusConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.verify = bool(cfg.verify_ssl)
        if cfg.access_key and cfg.secret_key:
            self.session.headers.update({
                "X-ApiKeys": f"accessKey={cfg.access_key}; secretKey={cfg.secret_key}",
                "Content-Type": "application/json",
            })

    def _url(self, path: str) -> str:
        return f"{self.cfg.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, **kwargs):
        response = self.session.request(method, self._url(path), timeout=35, **kwargs)
        response.raise_for_status()
        if response.content:
            return response.json()
        return {}

    def ping(self) -> dict:

        return self._request("GET", "/server/status")

    def list_templates(self) -> list[dict]:
        data = self._request("GET", "/editor/scan/templates")
        return data.get("templates") or []

    def create_scan(self, targets: list[str], folder_id: int | None = None) -> dict:
        settings = {
            "name": self.cfg.scan_name,
            "enabled": False,
            "text_targets": ",".join(targets),
        }
        if folder_id is not None:
            settings["folder_id"] = int(folder_id)

        payload = {
            "uuid": self.cfg.template_uuid,
            "settings": settings,
        }
        return self._request("POST", "/scans", data=json.dumps(payload))

    def launch_scan(self, scan_id: int) -> dict:
        return self._request("POST", f"/scans/{scan_id}/launch")

    def get_scan(self, scan_id: int) -> dict:
        return self._request("GET", f"/scans/{scan_id}")

    def list_vulnerabilities(self, scan_id: int) -> list[dict]:
        scan = self.get_scan(scan_id)
        vulns = (scan.get("vulnerabilities") or [])
        out = []
        for row in vulns:
            sev_name = str(row.get("severity") or "info").lower()
            out.append({
                "plugin_id": row.get("plugin_id"),
                "plugin_name": row.get("plugin_name") or row.get("plugin_family") or "",
                "severity": SEV_MAP.get(sev_name, "Media"),
                "count": row.get("count", 1),
                "cve": row.get("cve") or "",
                "cvss": row.get("cvss3_base_score") or row.get("cvss_base_score") or "",
                "software": row.get("plugin_family") or "",
            })
        return out


def _emit(progress_callback, **kwargs):
    if progress_callback:
        progress_callback(kwargs)


def _select_template_uuid(configured_uuid: str, templates: list[dict]) -> tuple[str, str]:
    available = [str(t.get("uuid") or "").strip() for t in templates if str(t.get("uuid") or "").strip()]
    names = {str(t.get("uuid") or "").strip(): str(t.get("name") or "") for t in templates}

    configured_uuid = str(configured_uuid or "").strip()
    if configured_uuid and configured_uuid not in {"basic", "default"} and configured_uuid in available:
        return configured_uuid, f"manual:{names.get(configured_uuid, configured_uuid)}"

    network_templates = [
        t for t in templates
        if not str(t.get("name") or "").lower().startswith("agent")
    ]

    for t in network_templates:
        name = str(t.get("name") or "").lower()
        if "basic" in name and "scan" in name:
            return str(t.get("uuid") or ""), f"auto:{t.get('name')}"

    if network_templates:
        first = network_templates[0]
        return str(first.get("uuid") or ""), f"auto:{first.get('name')}"

    if available:
        first_uuid = available[0]
        return first_uuid, f"fallback:{names.get(first_uuid, first_uuid)}"

    return "", "none"


def normalize_nessus_results(vulns: list[dict], scan_id: int, mode: str) -> list[dict]:
    if not vulns:
        return [{
            "control": "Nessus/Tenable vulnerability scan",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se reportaron vulnerabilidades en el escaneo Nessus/Tenable.",
            "evidence": f"scan_id={scan_id} | mode={mode}",
            "recommendation": "Mantener ciclo de escaneo periódico y validación manual de servicios críticos.",
        }]

    rows = []
    for vuln in vulns[:120]:
        sev = vuln.get("severity", "Media")
        status = "Posible hallazgo" if sev in {"Crítica", "Alta", "Media"} else "Detectado"
        rows.append({
            "control": f"Nessus plugin {vuln.get('plugin_id')}",
            "status": status,
            "severity": sev,
            "description": vuln.get("plugin_name", "Vulnerabilidad detectada por Nessus/Tenable."),
            "evidence": (
                f"Plugin: {vuln.get('plugin_id')} | CVE: {vuln.get('cve','')} | "
                f"CVSS: {vuln.get('cvss','')} | Conteo: {vuln.get('count',1)}"
            ),
            "recommendation": "Corregir según advisory del plugin y validar exposición explotable en contexto.",
        })

    rows.append({
        "control": "Nessus export estructurado",
        "status": "Detectado",
        "severity": "Informativa",
        "description": "Vulnerabilidades de Nessus/Tenable normalizadas para correlación de riesgo.",
        "evidence": json.dumps({"scan_id": scan_id, "vulns": len(vulns)}, ensure_ascii=False),
        "recommendation": "Incorporar estas señales al priorizador ofensivo y al plan de remediación.",
    })
    return rows


def run_nessus_assessment(
    targets: list[str],
    cfg: NessusConfig,
    progress_callback=None,
) -> tuple[list[dict], dict]:
    """Create, launch, poll and parse Nessus/Tenable scan with normalized output."""
    clean_targets = [str(t).strip() for t in (targets or []) if str(t).strip()]
    if not clean_targets:
        return ([{
            "control": "Nessus/Tenable vulnerability scan",
            "status": "No probado",
            "severity": "Informativa",
            "description": "Sin objetivos para Nessus/Tenable.",
            "evidence": "Lista de targets vacía.",
            "recommendation": "Alimentar targets desde discovery/Nmap antes de lanzar Nessus.",
        }], {"scan_id": None, "vulnerabilities": []})

    if not cfg.access_key or not cfg.secret_key:
        return ([{
            "control": "Nessus/Tenable vulnerability scan",
            "status": "No probado",
            "severity": "Informativa",
            "description": "Credenciales API Nessus/Tenable no configuradas.",
            "evidence": "Faltan access_key/secret_key.",
            "recommendation": "Configurar claves API para activar integración Nessus/Tenable.",
        }], {"scan_id": None, "vulnerabilities": []})

    client = NessusClient(cfg)

    try:
        status = client.ping()
        _emit(progress_callback, stage="nessus-ping", detail=str(status))
    except Exception as exc:
        return ([{
            "control": "Nessus/Tenable connectivity",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudo conectar con API Nessus/Tenable.",
            "evidence": str(exc),
            "recommendation": "Verificar URL, certificados SSL y credenciales API.",
        }], {"scan_id": None, "vulnerabilities": []})

    try:
        templates = client.list_templates()
    except Exception as exc:
        return ([{
            "control": "Nessus/Tenable templates",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudo consultar plantillas de escaneo en Nessus/Tenable.",
            "evidence": str(exc),
            "recommendation": "Validar permisos API para /editor/scan/templates.",
        }], {"scan_id": None, "vulnerabilities": []})

    selected_uuid, selection_source = _select_template_uuid(cfg.template_uuid, templates)
    if not selected_uuid:
        return ([{
            "control": "Nessus/Tenable templates",
            "status": "Error",
            "severity": "Media",
            "description": "No hay plantillas disponibles para crear escaneo Nessus.",
            "evidence": "templates=0",
            "recommendation": "Revisar licencia/feed/permisos de usuario API en Nessus.",
        }], {"scan_id": None, "vulnerabilities": []})

    cfg.template_uuid = selected_uuid
    _emit(progress_callback, stage="nessus-template", detail=f"uuid={selected_uuid} | source={selection_source}")

    try:
        create = client.create_scan(clean_targets, folder_id=None)
        scan = create.get("scan") or {}
        scan_id = int(scan.get("id"))
    except Exception as exc:
        template_names = [str(t.get("name") or "") for t in templates[:8]]
        return ([{
            "control": "Nessus/Tenable create scan",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudo crear escaneo en Nessus/Tenable.",
            "evidence": (
                f"{exc} | template={selected_uuid} ({selection_source}) | "
                f"templates={', '.join(template_names) if template_names else 'sin templates'}"
            ),
            "recommendation": "Revisar permisos API de creación de scans y disponibilidad de plantillas no-agent.",
        }], {"scan_id": None, "vulnerabilities": []})

    try:
        launch = client.launch_scan(scan_id)
        _emit(progress_callback, stage="nessus-launch", scan_id=scan_id, detail=str(launch))
    except Exception as exc:
        return ([{
            "control": "Nessus/Tenable launch scan",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudo lanzar el escaneo Nessus/Tenable.",
            "evidence": f"scan_id={scan_id} | {exc}",
            "recommendation": "Verificar estado de motor Nessus y límite de escaneos concurrentes.",
        }], {"scan_id": scan_id, "vulnerabilities": []})


    started = time.time()
    last_progress = ""

    while True:
        elapsed = int(time.time() - started)
        if elapsed > int(cfg.max_poll_seconds):
            return ([{
                "control": "Nessus/Tenable polling",
                "status": "Detectado",
                "severity": "Informativa",
                "description": "Escaneo Nessus en curso; polling detenido por ventana máxima configurada.",
                "evidence": f"scan_id={scan_id} | elapsed={elapsed}s",
                "recommendation": "Consultar estado posteriormente y descargar resultados cuando finalice.",
            }], {"scan_id": scan_id, "vulnerabilities": [], "status": "running"})

        try:
            scan_data = client.get_scan(scan_id)
        except Exception as exc:
            return ([{
                "control": "Nessus/Tenable polling",
                "status": "Error",
                "severity": "Media",
                "description": "Error consultando estado de escaneo Nessus/Tenable.",
                "evidence": f"scan_id={scan_id} | {exc}",
                "recommendation": "Revisar conectividad API y repetir polling.",
            }], {"scan_id": scan_id, "vulnerabilities": []})

        info = scan_data.get("info") or {}
        status = str(info.get("status") or "unknown").lower()
        progress = str(info.get("scan_progress_total") or info.get("progress") or "")

        if progress != last_progress:
            _emit(
                progress_callback,
                stage="nessus-poll",
                scan_id=scan_id,
                progress=progress,
                detail=f"status={status}",
            )
            last_progress = progress

        if status in {"completed", "canceled", "cancelled", "aborted", "stopped"}:
            break

        time.sleep(max(2, int(cfg.poll_interval_seconds)))

    try:
        vulns = client.list_vulnerabilities(scan_id)
        rows = normalize_nessus_results(vulns, scan_id=scan_id, mode=cfg.mode)
        return rows, {"scan_id": scan_id, "vulnerabilities": vulns, "status": "completed"}
    except Exception as exc:
        return ([{
            "control": "Nessus/Tenable parse results",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudieron parsear vulnerabilidades del escaneo.",
            "evidence": f"scan_id={scan_id} | {exc}",
            "recommendation": "Revisar formato de respuesta API y versión de Nessus/Tenable.",
        }], {"scan_id": scan_id, "vulnerabilities": [], "status": "completed"})
