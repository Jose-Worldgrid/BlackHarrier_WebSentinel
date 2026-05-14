from urllib.parse import urlparse
import socket
import time
import re

from scanner.http_client import HttpClient


def _resolve_host_with_retry(host: str, retries: int = 3, delay: float = 0.5):
    """Resolve host with retries and IPv6 support. Returns (ipv4_list, ipv6_list, aliases, reverse)."""
    ipv4, ipv6, aliases, reverse_dns = [], [], [], "No disponible"
    last_exc = None

    for attempt in range(retries):
        try:
            name, host_aliases, addresses = socket.gethostbyname_ex(host)
            aliases = list(host_aliases or [])
            ipv4 = sorted(set(addresses or []))

            if ipv4:
                try:
                    reverse_dns = socket.gethostbyaddr(ipv4[0])[0]
                except Exception:
                    pass

            try:
                for addrinfo in socket.getaddrinfo(host, None, socket.AF_INET6):
                    candidate = addrinfo[4][0]
                    if candidate and candidate not in ipv6 and not candidate.startswith("::ffff:"):
                        ipv6.append(candidate)
            except Exception:
                pass

            return ipv4, ipv6, aliases, reverse_dns, None

        except socket.gaierror as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(delay)

    return [], [], [], "No disponible", last_exc


def scan_network_recon(url: str):
    """Passive network reconnaissance: DNS, IP, PTR, banner, hosting exposure."""
    results = []
    parsed = urlparse(str(url or "").strip())
    host = parsed.hostname or ""

    if not host:
        return [{
            "control": "Recon de red e infraestructura",
            "status": "Error",
            "severity": "Baja",
            "description": "No se pudo extraer el host de la URL objetivo.",
            "evidence": f"URL recibida: {url}",
            "recommendation": "Introducir una URL válida con dominio o IP.",
        }]

    # Skip resolution for bare IPs — already resolved
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

    if is_ip:
        ipv4 = [host]
        ipv6, aliases = [], []
        try:
            reverse_dns = socket.gethostbyaddr(host)[0]
        except Exception:
            reverse_dns = "No disponible"
        last_exc = None
    else:
        ipv4, ipv6, aliases, reverse_dns, last_exc = _resolve_host_with_retry(host)

    if last_exc and not ipv4:
        results.append({
            "control": "Resolución DNS/IP",
            "status": "Error",
            "severity": "Baja",
            "description": "No se pudo resolver DNS/IP del objetivo.",
            "evidence": f"Host: {host} | Error: {last_exc}",
            "recommendation": "Verificar DNS del sistema, conectividad y que el dominio esté activo.",
        })
    else:
        evidence_parts = [f"Host: {host}"]
        if aliases:
            evidence_parts.append(f"CNAME/aliases: {', '.join(aliases[:5])}")
        if ipv4:
            evidence_parts.append(f"IPv4: {', '.join(ipv4[:8])}")
        if ipv6:
            evidence_parts.append(f"IPv6: {', '.join(ipv6[:4])}")
        evidence_parts.append(f"Reverse DNS: {reverse_dns}")

        # CDN / hosting fingerprint
        cdn_hints = {"cloudflare", "akamai", "fastly", "amazon", "azure", "google", "cdn"}
        cdn_found = any(h in reverse_dns.lower() for h in cdn_hints)
        if cdn_found:
            evidence_parts.append(f"CDN/Cloud detectado: {reverse_dns}")

        results.append({
            "control": "Resolución DNS/IP",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Resolución de red completada. Se identificaron IPs y PTR del objetivo.",
            "evidence": " | ".join(evidence_parts),
            "recommendation": (
                "Mapear todos los activos asociados a estas IPs. "
                "Si CDN activo, considerar técnicas de bypass (subdomains, historical DNS)."
            ),
        })

    # HTTP banner enumeration
    client = HttpClient()
    try:
        response = client.get(url)
        headers = response.headers
        server = headers.get("Server") or ""
        powered = headers.get("X-Powered-By") or ""
        via = headers.get("Via") or ""
        x_runtime = headers.get("X-Runtime") or ""
        x_aspnet = headers.get("X-AspNet-Version") or ""
        x_generator = headers.get("X-Generator") or ""

        exposed = [
            f"Server: {server}" if server else None,
            f"X-Powered-By: {powered}" if powered else None,
            f"Via: {via}" if via else None,
            f"X-Runtime: {x_runtime}" if x_runtime else None,
            f"X-AspNet-Version: {x_aspnet}" if x_aspnet else None,
            f"X-Generator: {x_generator}" if x_generator else None,
        ]
        exposed_clean = [e for e in exposed if e]

        if exposed_clean:
            results.append({
                "control": "Exposición de versiones/servicios",
                "status": "Posible hallazgo",
                "severity": "Media",
                "description": "Cabeceras HTTP revelan tecnologías y versiones del servidor.",
                "evidence": " | ".join(exposed_clean),
                "recommendation": (
                    "Configurar el servidor para suprimir cabeceras informativas "
                    "(ServerTokens Prod en Apache, server_tokens off en Nginx)."
                ),
            })
        else:
            results.append({
                "control": "Exposición de versiones/servicios",
                "status": "No evidenciado",
                "severity": "Informativa",
                "description": "No se detectó exposición de banners de servidor.",
                "evidence": f"HTTP {response.status_code} | Cabeceras revisadas sin versiones expuestas.",
                "recommendation": "Mantener configuración. Verificar periódicamente.",
            })

    except Exception as exc:
        results.append({
            "control": "Exposición de versiones/servicios",
            "status": "Error",
            "severity": "Baja",
            "description": "No se pudo obtener cabeceras HTTP del objetivo.",
            "evidence": str(exc),
            "recommendation": "Verificar conectividad, SSL/TLS y accesibilidad del host.",
        })

    return results

