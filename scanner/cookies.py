from requests import RequestException

from scanner.http_client import HttpClient


def scan_cookies(url: str):
    results = []
    client = HttpClient(timeout=10)

    try:
        response = client.get(url, allow_redirects=True)
        cookies = response.cookies

        if not cookies:
            return [{
                "control": "Cookies",
                "status": "Sin cookies",
                "severity": "Informativa",
                "description": "No se identificaron cookies en la respuesta inicial.",
                "evidence": "Sin cookies Set-Cookie.",
                "recommendation": "No aplica."
            }]

        for cookie in cookies:
            flags = []

            if not cookie.secure:
                flags.append("Falta Secure")

            if "httponly" not in str(response.headers.get("Set-Cookie", "")).lower():
                flags.append("Falta HttpOnly")

            if "samesite" not in str(response.headers.get("Set-Cookie", "")).lower():
                flags.append("Falta SameSite")

            if flags:
                results.append({
                    "control": f"Cookie {cookie.name}",
                    "status": "Hallazgo",
                    "severity": "Media",
                    "description": "Cookie con atributos de seguridad incompletos.",
                    "evidence": ", ".join(flags),
                    "recommendation": "Configurar Secure, HttpOnly y SameSite=Lax/Strict según corresponda."
                })
            else:
                results.append({
                    "control": f"Cookie {cookie.name}",
                    "status": "Correcto",
                    "severity": "Informativa",
                    "description": "Cookie con atributos de seguridad adecuados.",
                    "evidence": str(cookie),
                    "recommendation": "Mantener configuración."
                })

    except RequestException as exc:
        results.append({
            "control": "Cookies",
            "status": "Error",
            "severity": "Alta",
            "description": "No se pudieron analizar las cookies.",
            "evidence": str(exc),
            "recommendation": "Verificar disponibilidad del objetivo."
        })

    return results