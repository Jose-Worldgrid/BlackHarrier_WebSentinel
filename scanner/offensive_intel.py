import json
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
