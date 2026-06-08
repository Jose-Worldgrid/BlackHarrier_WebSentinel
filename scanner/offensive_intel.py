# Modulo de escaneo y analisis para offensive intel.

import json
import ipaddress
import re
from urllib.parse import urlparse


_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_TECH = re.compile(
    r"(apache|nginx|php|wordpress|drupal|tomcat|iis|openresty|node|express|django|laravel|spring)",
    re.IGNORECASE,
)


def _clean_host(value: str) -> str:
    parsed = urlparse(str(value or "").strip())
    host = parsed.hostname or str(value or "").strip()
    return host.lower()


def _clean_url(value: str) -> str:
    text = str(value or "").strip()
    if text.startswith("http://") or text.startswith("https://"):
        return text
    return ""


def collect_external_scan_targets(target_url: str, pages: list, discovery: dict, results: list) -> dict:
    """Collect high-value targets for network/vuln scanners from existing pipeline artifacts."""
    hosts = set()
    urls = set()
    sensitive_endpoints = set()
    technologies = set()

    base_host = _clean_host(target_url)
    if base_host:
        hosts.add(base_host)

    if _clean_url(target_url):
        urls.add(_clean_url(target_url))

    for page in pages or []:
        for raw in [page.get("url"), page.get("final_url")]:
            url = _clean_url(raw)
            if not url:
                continue
            urls.add(url)
            host = _clean_host(url)
            if host:
                hosts.add(host)

            cls = str(page.get("classification", ""))
            if cls in {"admin_candidate", "api_candidate", "sensitive_candidate", "protected", "protected_redirect_to_auth"}:
                sensitive_endpoints.add(url)

        ai_ctx = page.get("ai_context") or {}
        for endpoint in ai_ctx.get("candidate_endpoints") or []:
            ep = _clean_url(endpoint)
            if ep:
                urls.add(ep)
                sensitive_endpoints.add(ep)
                host = _clean_host(ep)
                if host:
                    hosts.add(host)

    discovered = (discovery or {}).get("discovered") or []
    for raw in discovered:
        url = _clean_url(raw)
        if not url:
            continue
        urls.add(url)
        host = _clean_host(url)
        if host:
            hosts.add(host)

    for item in results or []:
        evidence = str(item.get("Evidencia", "") or "")
        description = str(item.get("Descripción", "") or "")
        text = f"{evidence} {description}"

        for ip in _RE_IP.findall(text):
            hosts.add(ip)

        for match in _RE_TECH.findall(text):
            technologies.add(match.lower())

        for token in text.replace("|", " ").split():
            candidate = token.strip(" ,;()[]{}<>'\"")
            if candidate.startswith("http://") or candidate.startswith("https://"):
                urls.add(candidate)
                host = _clean_host(candidate)
                if host:
                    hosts.add(host)

    return {
        "primary_target": target_url,
        "hosts": sorted(hosts),
        "urls": sorted(urls),
        "sensitive_endpoints": sorted(sensitive_endpoints),
        "technologies": sorted(technologies),
    }


def build_ai_recon_contract(targets: dict, nmap_data: dict | None = None, nessus_data: dict | None = None) -> dict:
    """Internal contract for future AI offensive prioritization (no external AI call yet)."""
    nmap_data = nmap_data or {}
    nessus_data = nessus_data or {}

    cves = []
    plugins = []
    software = []
    ports = []
    services = []

    for host in nmap_data.get("hosts", []):
        for port in host.get("ports", []):
            ports.append({
                "host": host.get("host"),
                "port": port.get("port"),
                "protocol": port.get("protocol"),
                "state": port.get("state"),
            })
            if port.get("service"):
                services.append({
                    "host": host.get("host"),
                    "port": port.get("port"),
                    "name": port.get("service"),
                    "product": port.get("product"),
                    "version": port.get("version"),
                })

    for vuln in nessus_data.get("vulnerabilities", []):
        if vuln.get("cve"):
            cves.append(vuln.get("cve"))
        if vuln.get("plugin_id"):
            plugins.append(vuln.get("plugin_id"))
        if vuln.get("software"):
            software.append(vuln.get("software"))

    contract = {
        "targets": targets,
        "recon": {
            "open_ports": ports,
            "services": services,
            "nmap_hosts": nmap_data.get("hosts", []),
        },
        "vulnerabilities": {
            "cves": sorted(set([x for x in cves if x])),
            "nessus_plugins": sorted(set([x for x in plugins if x])),
            "software": sorted(set([x for x in software if x])),
            "raw": nessus_data.get("vulnerabilities", []),
        },
        "meta": {
            "ready_for_ai_planner": True,
            "schema_version": "1.0",
        },
    }
    return contract


def contract_to_result(contract: dict) -> dict:
    """Emit one normalized result row to keep the AI contract in the report/pipeline."""
    ports = contract.get("recon", {}).get("open_ports", [])
    cves = contract.get("vulnerabilities", {}).get("cves", [])
    services = contract.get("recon", {}).get("services", [])

    evidence = {
        "hosts": contract.get("targets", {}).get("hosts", []),
        "ports": len(ports),
        "services": len(services),
        "cves": cves[:20],
        "ready_for_ai_planner": True,
    }

    severity = "Informativa"
    status = "Detectado"
    if len(cves) >= 5:
        severity = "Alta"
        status = "Posible hallazgo"
    elif cves:
        severity = "Media"
        status = "Posible hallazgo"

    return {
        "control": "Contrato de correlación ofensiva para IA",
        "status": status,
        "severity": severity,
        "description": "Contexto técnico consolidado para priorización de ataque y correlación futura asistida por IA.",
        "evidence": json.dumps(evidence, ensure_ascii=False),
        "recommendation": "Usar este contrato como entrada para el planner IA de priorización y reducción de falsos positivos.",
    }


_COMMON_THIRD_PARTY_HINTS = (
    "cloudflare",
    "akamai",
    "fastly",
    "amazonaws",
    "azureedge",
    "googleusercontent",
    "github.io",
    "netlify",
    "vercel",
    "herokuapp",
)


_DB_SERVICE_HINTS = {
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgres": "PostgreSQL",
    "postgresql": "PostgreSQL",
    "mongodb": "MongoDB",
    "mongo": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "opensearch": "OpenSearch",
    "oracle": "Oracle",
    "mssql": "MSSQL",
    "sql server": "MSSQL",
    "db2": "DB2",
    "cassandra": "Cassandra",
}


_DB_PORT_HINTS = {
    1433: "MSSQL",
    1521: "Oracle",
    27017: "MongoDB",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9042: "Cassandra",
    9200: "Elasticsearch",
}


def _registrable_domain(host: str) -> str:
    host = str(host or "").strip().lower()
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except Exception:
        pass
    parts = [p for p in host.split(".") if p]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(host or "").strip())
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception:
        return False


def _owner_classification(host: str, base_domain: str) -> dict:
    host = str(host or "").strip().lower()
    if not host:
        return {
            "owner": "unknown",
            "confidence": 0.2,
            "reason": "Activo sin hostname/IP normalizable.",
        }

    if _is_private_ip(host):
        return {
            "owner": "first_party",
            "confidence": 0.9,
            "reason": "IP privada asociada al objetivo interno.",
        }

    if any(hint in host for hint in _COMMON_THIRD_PARTY_HINTS):
        return {
            "owner": "third_party",
            "confidence": 0.8,
            "reason": "Hostname compatible con infraestructura CDN/SaaS de terceros.",
        }

    host_domain = _registrable_domain(host)
    if base_domain and host_domain and host_domain == base_domain:
        return {
            "owner": "first_party",
            "confidence": 0.85,
            "reason": "Coincidencia de dominio registrable con el objetivo principal.",
        }

    if base_domain and host.endswith(f".{base_domain}"):
        return {
            "owner": "first_party",
            "confidence": 0.75,
            "reason": "Subdominio del dominio objetivo.",
        }

    return {
        "owner": "unknown",
        "confidence": 0.45,
        "reason": "No hay evidencia suficiente de pertenencia first-party.",
    }


def _extract_api_versions(urls: list[str]) -> list[str]:
    versions = set()
    for url in urls or []:
        text = str(url or "").lower()
        for match in re.findall(r"/v(\d{1,3})(?:/|$)", text):
            versions.add(f"v{match}")
    return sorted(versions)


def _extract_db_assets_from_nmap(nmap_data: dict) -> list[dict]:
    assets = []
    for host in (nmap_data or {}).get("hosts") or []:
        host_ip = str(host.get("host") or "")
        for p in host.get("ports") or []:
            if str(p.get("state") or "").lower() != "open":
                continue
            port = int(p.get("port") or 0)
            service_name = str(p.get("service") or "").lower()
            product = str(p.get("product") or "")
            version = str(p.get("version") or "")

            db_family = ""
            for key, label in _DB_SERVICE_HINTS.items():
                if key in service_name or key in product.lower():
                    db_family = label
                    break
            if not db_family and port in _DB_PORT_HINTS:
                db_family = _DB_PORT_HINTS[port]
            if not db_family:
                continue

            assets.append({
                "host": host_ip,
                "port": port,
                "protocol": str(p.get("protocol") or "tcp"),
                "db_family": db_family,
                "service": str(p.get("service") or ""),
                "product": product,
                "version": version,
            })
    return assets


def _candidate_severity(score: float) -> str:
    if score >= 9:
        return "Crítica"
    if score >= 7:
        return "Alta"
    if score >= 4:
        return "Media"
    return "Baja"


def build_asset_intel_rows(*, target_url: str, external_targets: dict, nmap_data: dict, discovered_urls: list, cves: list) -> tuple[list[dict], list[dict]]:
    """Build ownership map, service/version profile and prioritized candidate targets."""
    rows = []
    candidate_targets = []

    base_host = _clean_host(target_url)
    base_domain = _registrable_domain(base_host)

    hosts = list((external_targets or {}).get("hosts") or [])
    ownership_counts = {
        "first_party": 0,
        "third_party": 0,
        "unknown": 0,
    }

    classified_hosts = []
    for host in hosts:
        cls = _owner_classification(host, base_domain)
        owner = str(cls.get("owner") or "unknown")
        if owner not in ownership_counts:
            owner = "unknown"
        ownership_counts[owner] += 1
        classified_hosts.append({
            "host": str(host),
            "owner": owner,
            "confidence": float(cls.get("confidence", 0.0) or 0.0),
            "reason": str(cls.get("reason") or ""),
        })

    rows.append({
        "control": "Mapa de pertenencia de activos",
        "status": "Detectado" if classified_hosts else "No evidenciado",
        "severity": "Informativa",
        "description": "Clasificación de hosts/IP relacionados con el objetivo por pertenencia estimada.",
        "evidence": json.dumps({
            "base_domain": base_domain,
            "total_hosts": len(classified_hosts),
            "owners": ownership_counts,
            "sample": classified_hosts[:12],
        }, ensure_ascii=False),
        "recommendation": "Validar ownership legal/técnico de activos unknown antes de ampliar alcance de auditoría.",
    })

    public_ips = []
    for host in hosts:
        try:
            ip = ipaddress.ip_address(str(host))
        except Exception:
            continue
        if ip.version == 4 and not (ip.is_private or ip.is_loopback or ip.is_link_local):
            public_ips.append(str(ip))

    cidr24 = sorted(set([".".join(ip.split(".")[:3]) + ".0/24" for ip in public_ips]))
    if cidr24:
        rows.append({
            "control": "Redes relacionadas detectadas",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Agrupación de IPs públicas relacionadas en bloques /24 para investigación de superficie.",
            "evidence": json.dumps({"public_ips": public_ips[:30], "cidr24": cidr24[:20]}, ensure_ascii=False),
            "recommendation": "Usar los bloques como cola de descubrimiento validando autorización explícita por red.",
        })

    api_versions = _extract_api_versions(discovered_urls or [])
    if api_versions:
        rows.append({
            "control": "Versionado de API detectado",
            "status": "Detectado",
            "severity": "Media",
            "description": "Se detectaron patrones de versionado en endpoints API expuestos.",
            "evidence": f"Versiones API: {', '.join(api_versions[:10])} | Endpoints analizados: {len(discovered_urls or [])}",
            "recommendation": "Revisar endpoints legacy (v1/v2) y alinear políticas de authN/authZ y deprecación.",
        })

    db_assets = _extract_db_assets_from_nmap(nmap_data or {})
    if db_assets:
        rows.append({
            "control": "Servicios de base de datos expuestos",
            "status": "Posible hallazgo",
            "severity": "Alta",
            "description": "Se identificaron servicios BBDD expuestos por red con versión/banner detectable.",
            "evidence": json.dumps(db_assets[:20], ensure_ascii=False),
            "recommendation": "Restringir acceso por segmentación, exigir autenticación fuerte y parchear versiones EOL.",
        })

    cves_by_service = {}
    for cve in cves or []:
        service = str(cve.get("service") or "unknown").strip().lower()
        score = float(cve.get("score", 0) or 0)
        if service not in cves_by_service or score > float(cves_by_service[service].get("score", 0) or 0):
            cves_by_service[service] = cve

    for db in db_assets:
        svc = str(db.get("product") or db.get("service") or db.get("db_family") or "").strip().lower()
        cve = cves_by_service.get(svc) or cves_by_service.get(str(db.get("db_family") or "").lower())
        score = float(cve.get("score", 0) or 0) if isinstance(cve, dict) else 5.0
        score += 1.5
        candidate_targets.append({
            "target": f"{db.get('host')}:{db.get('port')}",
            "kind": "database-service",
            "owner": _owner_classification(str(db.get("host") or ""), base_domain).get("owner"),
            "priority_score": round(min(score, 10.0), 1),
            "reason": f"{db.get('db_family')} expuesto con versión {db.get('version') or 'desconocida'}.",
        })

    for host_obj in classified_hosts:
        if host_obj["owner"] == "unknown" and host_obj["confidence"] < 0.6:
            continue
        candidate_targets.append({
            "target": host_obj["host"],
            "kind": "related-host",
            "owner": host_obj["owner"],
            "priority_score": round(6.0 * host_obj["confidence"], 1),
            "reason": host_obj["reason"],
        })

    for url in (external_targets or {}).get("sensitive_endpoints") or []:
        text = str(url).lower()
        if any(token in text for token in ("/admin", "/api", "/auth", "/login", "/internal", "/panel")):
            candidate_targets.append({
                "target": str(url),
                "kind": "sensitive-endpoint",
                "owner": "first_party" if (base_domain and base_domain in text) else "unknown",
                "priority_score": 7.0,
                "reason": "Endpoint sensible descubierto en crawling/discovery.",
            })


    dedup = {}
    for ct in candidate_targets:
        key = f"{ct.get('kind')}::{ct.get('target')}"
        current = dedup.get(key)
        if current is None or float(ct.get("priority_score", 0) or 0) > float(current.get("priority_score", 0) or 0):
            dedup[key] = ct
    candidate_targets = sorted(
        dedup.values(),
        key=lambda x: float(x.get("priority_score", 0) or 0),
        reverse=True,
    )

    if candidate_targets:
        top = candidate_targets[:15]
        rows.append({
            "control": "Objetivos candidatos priorizados",
            "status": "Detectado",
            "severity": _candidate_severity(float(top[0].get("priority_score", 0) or 0)),
            "description": "Cola de activos/endpoints para validación técnica priorizada por exposición y riesgo.",
            "evidence": json.dumps(top, ensure_ascii=False),
            "recommendation": "Validar solo bajo autorización formal del activo objetivo y registrar evidencia de cada prueba.",
        })

    return rows, candidate_targets
