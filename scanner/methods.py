from scanner.http_client import HttpClient


DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def scan_http_methods(url: str):
    client = HttpClient()
    results = []

    try:
        response = client.options(url, timeout=10, allow_redirects=True)
        allow = response.headers.get("Allow", "")

        enabled = {m.strip().upper() for m in allow.split(",") if m.strip()}
        dangerous = enabled.intersection(DANGEROUS_METHODS)

        if dangerous:
            results.append({
                "control": "Métodos HTTP habilitados",
                "status": "Hallazgo",
                "severity": "Alta" if "TRACE" in dangerous else "Media",
                "description": "Se detectaron métodos HTTP potencialmente peligrosos.",
                "evidence": f"Allow: {allow}",
                "recommendation": "Deshabilitar métodos no necesarios, especialmente TRACE, PUT, DELETE y CONNECT."
            })
        else:
            results.append({
                "control": "Métodos HTTP habilitados",
                "status": "No evidenciado",
                "severity": "Informativa",
                "description": "No se detectaron métodos peligrosos mediante OPTIONS.",
                "evidence": f"Allow: {allow or 'No informado'}",
                "recommendation": "Mantener únicamente métodos requeridos por la aplicación."
            })

    except Exception as exc:
        results.append({
            "control": "Métodos HTTP habilitados",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudo comprobar métodos HTTP.",
            "evidence": str(exc),
            "recommendation": "Verificar conectividad."
        })

    return results