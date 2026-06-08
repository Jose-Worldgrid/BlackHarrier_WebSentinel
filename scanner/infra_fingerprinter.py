# Modulo de fingerprint de infraestructura para resolver IPs, clasificar plataforma y detectar exposicion perimetral.

import ipaddress
import socket
import ssl
from urllib.parse import urlparse


_DB_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1521: "Oracle",
    1433: "MSSQL",
}

_ADMIN_PORTS = {
    21: "FTP",
    22: "SSH",
    3389: "RDP",
}

_BANNER_PORTS = {80, 443, 8080, 3128, 8443}


def _normalize_target(url_completa: str):
    text = str(url_completa or "").strip()
    if not text:
        return "", "", ["URL objetivo vacia"]
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    parsed = urlparse(text)
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return "", text, ["No se pudo extraer hostname valido"]
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
    return hostname, normalized, []


def _resolve_ips(hostname: str):
    ips = []
    errors = []
    try:
        info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen = set()
        for row in info:
            sockaddr = row[4] or ()
            if not sockaddr:
                continue
            ip = str(sockaddr[0] or "").strip()
            if not ip or ip in seen:
                continue
            seen.add(ip)
            ips.append(ip)
    except Exception as exc:
        errors.append(f"Fallo DNS/getaddrinfo: {type(exc).__name__}: {exc}")
    return ips, errors


def _is_public_ip(ip_text: str) -> bool:
    try:
        return ipaddress.ip_address(ip_text).is_global
    except Exception:
        return False


def _extract_dns_traces(hostname: str):
    traces = set()
    errors = []
    try:
        canonical, aliases, _ips = socket.gethostbyname_ex(hostname)
        if canonical:
            traces.add(str(canonical).strip().lower())
        for alias in aliases or []:
            alias_text = str(alias).strip().lower()
            if alias_text:
                traces.add(alias_text)

        for ip in _ips or []:
            try:
                fqdn = socket.getfqdn(ip)
                if fqdn and fqdn != ip:
                    traces.add(str(fqdn).strip().lower())
            except Exception:
                continue
    except Exception as exc:
        errors.append(f"Fallo en trazas DNS: {type(exc).__name__}: {exc}")
    return sorted(traces), errors


def _extract_http_traces(hostname: str):
    traces = set()
    errors = []
    probes = [(80, False), (443, True)]
    for port, use_tls in probes:
        try:
            sock = socket.create_connection((hostname, port), timeout=2.0)
            try:
                if use_tls:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    conn = context.wrap_socket(sock, server_hostname=hostname)
                else:
                    conn = sock

                request = (
                    f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\n"
                    "User-Agent: BlackHarrier/infra-fingerprinter\r\nConnection: close\r\n\r\n"
                ).encode("ascii", errors="ignore")
                conn.sendall(request)
                raw = conn.recv(4096)
                decoded = raw.decode(errors="ignore").lower()
                for marker in ("cloudflare", "cloudfront", "akamai", "zscaler"):
                    if marker in decoded:
                        traces.add(marker)
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
        except Exception as exc:
            errors.append(f"Fallo HTTP trace {port}: {type(exc).__name__}: {exc}")
    return sorted(traces), errors


def _base_classification(hostname: str, traces: list[str]):
    labels = []
    host = hostname.lower()
    blob = " ".join(traces).lower()

    if ".elb.amazonaws.com" in host:
        labels.append("Infraestructura: AWS Elastic Load Balancer (ELB) | Proveedor: Amazon Web Services (AWS)")
    if ".azurewebsites.net" in host or ".cloudapp.azure.com" in host:
        labels.append("Infraestructura: Cloud App Service | Proveedor: Microsoft Azure")
    if any(x in blob for x in ("cloudfront", "akamai", "cloudflare")):
        labels.append("Infraestructura: Red de Distribucion de Contenidos (CDN)")

    return labels


def _infer_pertenencia(labels: list[str]) -> str:
    blob = " | ".join(labels or []).lower()
    if "amazon web services" in blob or "aws" in blob:
        return "Amazon Web Services (AWS)"
    if "microsoft azure" in blob or "azure" in blob:
        return "Microsoft Azure"
    if "zscaler" in blob:
        return "Zscaler"
    if "cdn" in blob:
        return "CDN / proveedor de edge"
    return "Infraestructura objetivo / no concluyente"


def _read_banner(ip: str, port: int):
    try:
        sock = socket.create_connection((ip, port), timeout=1.0)
        try:
            if port in {443, 8443}:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = context.wrap_socket(sock, server_hostname=ip)
            else:
                conn = sock

            if port in _BANNER_PORTS:
                req = (
                    f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
                    "User-Agent: BlackHarrier/infra-fingerprinter\r\nConnection: close\r\n\r\n"
                ).encode("ascii", errors="ignore")
                conn.sendall(req)

            raw = conn.recv(2048)
            return raw.decode(errors="ignore")
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception:
        return ""


def _port_fingerprint(ip: str):
    open_ports = []
    labels = []
    services = []
    zscaler = False
    banner_hits = []

    ports_to_check = sorted(set(list(_DB_PORTS.keys()) + list(_ADMIN_PORTS.keys()) + list(_BANNER_PORTS)))
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            rc = sock.connect_ex((ip, port))
            sock.close()
            if rc != 0:
                continue
        except Exception:
            continue

        open_ports.append(port)

        if port in _DB_PORTS:
            services.append(_DB_PORTS[port])
            labels.append("Servicio de Base de Datos Detectado (Alerta de Exposicion)")
        if port in _ADMIN_PORTS:
            services.append(_ADMIN_PORTS[port])
            labels.append("Interfaz de Administracion Perimetral")

        banner = _read_banner(ip, port)
        if banner:
            banner_hits.append(f"{ip}:{port} -> {banner[:120].replace(chr(10), ' ').replace(chr(13), ' ')}")
        if "zscaler" in banner.lower():
            zscaler = True

    if zscaler:
        labels.append("Infraestructura: Sonda de Seguridad / Proxy Perimetral | Proveedor: Zscaler")

    labels = list(dict.fromkeys(labels))
    services = list(dict.fromkeys(services))
    return {
        "open_ports": open_ports,
        "labels": labels,
        "services": services,
        "banner_hits": banner_hits,
    }


def obtener_infraestructura(url_completa: str):
    hostname, normalized_url, parse_errors = _normalize_target(url_completa)

    result = {
        "hostname_limpio": hostname,
        "url_normalizada": normalized_url,
        "ips_resueltas": [],
        "ips_publicas": [],
        "clasificaciones": [],
        "etiquetas_globales": [],
        "evidencias": {
            "dns": [],
            "http": [],
            "banner": [],
            "puertos": {},
        },
        "infraestructura_por_ip": [],
        "errores": list(parse_errors),
    }

    if not hostname:
        return result

    ips, dns_errors = _resolve_ips(hostname)
    result["ips_resueltas"] = ips
    result["ips_publicas"] = [ip for ip in ips if _is_public_ip(ip)]
    result["errores"].extend(dns_errors)

    dns_traces, trace_dns_errors = _extract_dns_traces(hostname)
    http_traces, trace_http_errors = _extract_http_traces(hostname)
    traces = sorted(set(dns_traces + http_traces))
    result["evidencias"]["dns"] = dns_traces
    result["evidencias"]["http"] = http_traces
    result["errores"].extend(trace_dns_errors)
    result["errores"].extend(trace_http_errors)

    global_labels = _base_classification(hostname, traces)

    for ip in ips:
        ip_data = {
            "ip": ip,
            "tipo_ip": "publica" if _is_public_ip(ip) else "privada_o_no_publica",
            "clasificacion": list(global_labels),
            "pertenece_a": _infer_pertenencia(global_labels),
            "puertos_abiertos": [],
            "servicios_detectados": [],
        }

        if ":" not in ip:
            fp = _port_fingerprint(ip)
            ip_data["puertos_abiertos"] = fp["open_ports"]
            ip_data["servicios_detectados"] = fp["services"]
            result["evidencias"]["puertos"][ip] = list(fp["open_ports"])
            result["evidencias"]["banner"].extend(fp["banner_hits"])
            for label in fp["labels"]:
                if label not in ip_data["clasificacion"]:
                    ip_data["clasificacion"].append(label)
            ip_data["pertenece_a"] = _infer_pertenencia(ip_data["clasificacion"])

        for label in ip_data["clasificacion"]:
            if label not in global_labels:
                global_labels.append(label)

        result["infraestructura_por_ip"].append(ip_data)

    result["clasificaciones"] = list(global_labels)
    result["etiquetas_globales"] = list(global_labels)
    return result


def enriquecer_infraestructura_con_nmap(infraestructura_target: dict, nmap_structured: dict):
    infra = infraestructura_target or {}
    hosts = (nmap_structured or {}).get("hosts") or []
    ip_index = {
        str(item.get("ip") or ""): item
        for item in (infra.get("infraestructura_por_ip") or [])
        if item.get("ip")
    }
    etiquetas_globales = list(infra.get("etiquetas_globales") or [])
    evidencias = infra.get("evidencias") or {}
    puertos_ev = evidencias.get("puertos") or {}
    banners_ev = list(evidencias.get("banner") or [])

    for host in hosts:
        ip = str(host.get("host") or "").strip()
        if not ip:
            continue
        if ip not in ip_index:
            ip_index[ip] = {
                "ip": ip,
                "tipo_ip": "publica" if _is_public_ip(ip) else "privada_o_no_publica",
                "clasificacion": [],
                "pertenece_a": "Infraestructura objetivo / no concluyente",
                "puertos_abiertos": [],
                "servicios_detectados": [],
            }

        target = ip_index[ip]
        open_ports = []
        for port_item in host.get("ports") or []:
            if str(port_item.get("state") or "") != "open":
                continue
            port_num = int(port_item.get("port", 0) or 0)
            if port_num <= 0:
                continue
            open_ports.append(port_num)

            if port_num in _DB_PORTS and "Servicio de Base de Datos Detectado (Alerta de Exposicion)" not in target["clasificacion"]:
                target["clasificacion"].append("Servicio de Base de Datos Detectado (Alerta de Exposicion)")
            if port_num in _ADMIN_PORTS and "Interfaz de Administracion Perimetral" not in target["clasificacion"]:
                target["clasificacion"].append("Interfaz de Administracion Perimetral")

            service_name = str(port_item.get("service") or "").strip()
            if service_name and service_name not in target["servicios_detectados"]:
                target["servicios_detectados"].append(service_name)

            for script in port_item.get("scripts") or []:
                out = str(script.get("output") or "")
                if "zscaler" in out.lower():
                    label = "Infraestructura: Sonda de Seguridad / Proxy Perimetral | Proveedor: Zscaler"
                    if label not in target["clasificacion"]:
                        target["clasificacion"].append(label)
                    banners_ev.append(f"{ip}:{port_num} -> {out[:120].replace(chr(10), ' ').replace(chr(13), ' ')}")

        target["puertos_abiertos"] = sorted(set((target.get("puertos_abiertos") or []) + open_ports))
        target["pertenece_a"] = _infer_pertenencia(target.get("clasificacion") or [])
        puertos_ev[ip] = sorted(set((puertos_ev.get(ip) or []) + open_ports))

        for label in target.get("clasificacion") or []:
            if label not in etiquetas_globales:
                etiquetas_globales.append(label)

    infra["infraestructura_por_ip"] = list(ip_index.values())
    infra["etiquetas_globales"] = etiquetas_globales
    infra["clasificaciones"] = list(etiquetas_globales)
    evidencias["puertos"] = puertos_ev
    evidencias["banner"] = banners_ev
    infra["evidencias"] = evidencias
    return infra


def construir_hallazgos_infraestructura(infraestructura_target: dict):
    infra = infraestructura_target or {}
    rows = []

    hostname = str(infra.get("hostname_limpio") or "")
    ips_publicas = infra.get("ips_publicas") or []
    clas_global = infra.get("etiquetas_globales") or []

    rows.append({
        "control": "Fingerprint de infraestructura objetivo",
        "status": "Detectado" if hostname else "No detectado",
        "severity": "Informativa",
        "description": "Identificacion inicial de infraestructura y huella de plataforma antes de escaneos web.",
        "evidence": (
            f"Hostname: {hostname or 'no disponible'} | "
            f"IPs publicas: {', '.join(ips_publicas) if ips_publicas else 'ninguna'} | "
            f"Clasificacion: {' | '.join(clas_global) if clas_global else 'sin clasificacion'}"
        ),
        "recommendation": "Usar esta huella para priorizar pruebas por tipo de plataforma y superficie expuesta.",
    })

    for ip_entry in infra.get("infraestructura_por_ip") or []:
        ip = str(ip_entry.get("ip") or "")
        ports = ip_entry.get("puertos_abiertos") or []
        services = ip_entry.get("servicios_detectados") or []
        labels = ip_entry.get("clasificacion") or []

        severity = "Informativa"
        if any("Base de Datos" in lbl for lbl in labels):
            severity = "Alta"
        elif any("Interfaz de Administracion" in lbl for lbl in labels):
            severity = "Media"

        rows.append({
            "control": f"Perfil de infraestructura por IP {ip}",
            "status": "Detectado",
            "severity": severity,
            "description": "Clasificacion de infraestructura y servicios expuestos por direccion IP resuelta.",
            "evidence": (
                f"Tipo IP: {ip_entry.get('tipo_ip', '')} | "
                f"Pertenece a: {ip_entry.get('pertenece_a', 'no concluyente')} | "
                f"Puertos: {', '.join(str(p) for p in ports) if ports else 'sin puertos relevantes'} | "
                f"Servicios: {', '.join(services) if services else 'sin servicios clasificados'} | "
                f"Etiquetas: {' | '.join(labels) if labels else 'sin etiquetas'}"
            ),
            "recommendation": "Revisar exposicion perimetral y segmentacion de red en los servicios detectados.",
        })

    return rows
