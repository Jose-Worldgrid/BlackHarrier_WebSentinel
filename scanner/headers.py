from scanner.http_client import HttpClient


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Alta",
        "description": "Ausencia de HSTS. El sitio puede ser vulnerable a downgrade o interceptación.",
        "recommendation": "Configurar Strict-Transport-Security con max-age adecuado, includeSubDomains y preload si aplica."
    },
    "Content-Security-Policy": {
        "severity": "Alta",
        "description": "Ausencia de Content Security Policy. Aumenta el riesgo de XSS y carga de recursos no autorizados.",
        "recommendation": "Definir una CSP restrictiva adaptada a la aplicación."
    },
    "X-Frame-Options": {
        "severity": "Media",
        "description": "Ausencia de protección frente a clickjacking.",
        "recommendation": "Configurar X-Frame-Options: DENY o SAMEORIGIN."
    },
    "X-Content-Type-Options": {
        "severity": "Media",
        "description": "Ausencia de protección frente a MIME sniffing.",
        "recommendation": "Configurar X-Content-Type-Options: nosniff."
    },
    "Referrer-Policy": {
        "severity": "Baja",
        "description": "Ausencia de política de referer.",
        "recommendation": "Configurar Referrer-Policy: no-referrer o strict-origin-when-cross-origin."
    },
    "Permissions-Policy": {
        "severity": "Baja",
        "description": "Ausencia de Permissions-Policy.",
        "recommendation": "Definir una política restrictiva para cámara, micrófono, geolocalización y APIs sensibles."
    }
}


def scan_security_headers(url: str, client=None):
    client = client or HttpClient()
    results = []

    try:
        response = client.get(url)
        headers = response.headers

        for header, meta in SECURITY_HEADERS.items():
            if header in headers:
                results.append({
                    "control": header,
                    "status": "Correcto",
                    "severity": "Informativa",
                    "description": f"La cabecera {header} está presente.",
                    "evidence": f"{header}: {headers.get(header)}",
                    "recommendation": "Mantener configuración y revisar endurecimiento."
                })
            else:
                results.append({
                    "control": header,
                    "status": "Hallazgo",
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "evidence": f"Cabecera no presente. Status: {response.status_code}. URL final: {response.url}",
                    "recommendation": meta["recommendation"]
                })

    except Exception as exc:
        results.append({
            "control": "Conectividad",
            "status": "Error",
            "severity": "Alta",
            "description": "No se pudo conectar con el objetivo.",
            "evidence": str(exc),
            "recommendation": "Verificar URL, conectividad, certificados, WAF y bloqueo por User-Agent."
        })

    return results