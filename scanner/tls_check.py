import ssl
import socket
from urllib.parse import urlparse


def scan_tls(url: str):
    results = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return [{
            "control": "TLS/HTTPS",
            "status": "Hallazgo",
            "severity": "Alta",
            "description": "El objetivo no usa HTTPS.",
            "evidence": f"URL: {url}",
            "recommendation": "Forzar HTTPS y redirección segura desde HTTP."
        }]

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        results.append({
            "control": "Certificado TLS",
            "status": "Detectado",
            "severity": "Informativa",
            "description": "Certificado TLS válido desde la perspectiva del cliente.",
            "evidence": f"Issuer: {cert.get('issuer')} | NotAfter: {cert.get('notAfter')} | Cipher: {cipher}",
            "recommendation": "Mantener TLS actualizado, revisar expiración y configuración segura."
        })

    except Exception as exc:
        results.append({
            "control": "Certificado TLS",
            "status": "Hallazgo",
            "severity": "Alta",
            "description": "Error al validar certificado TLS.",
            "evidence": str(exc),
            "recommendation": "Revisar certificado, cadena de confianza, expiración y configuración TLS."
        })

    return results