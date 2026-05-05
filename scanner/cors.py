from scanner.http_client import HttpClient


def scan_cors(url: str):
    client = HttpClient()
    results = []

    try:
        headers = {
            "Origin": "https://evil.example"
        }

        response = client.get(url, headers=headers)

        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")

        if acao == "*" and str(acac).lower() == "true":
            severity = "Crítica"
            status = "Hallazgo"
            description = "CORS permite cualquier origen junto con credenciales."
        elif acao == "https://evil.example":
            severity = "Alta"
            status = "Hallazgo"
            description = "CORS refleja el origen arbitrario enviado por el cliente."
        elif acao == "*":
            severity = "Media"
            status = "Hallazgo"
            description = "CORS permite cualquier origen."
        else:
            severity = "Informativa"
            status = "No evidenciado"
            description = "No se detectó una configuración CORS permisiva en la respuesta inicial."

        results.append({
            "control": "Configuración CORS",
            "status": status,
            "severity": severity,
            "description": description,
            "evidence": f"Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}",
            "recommendation": "Restringir orígenes permitidos, evitar '*' y no combinar CORS amplio con credenciales."
        })

    except Exception as exc:
        results.append({
            "control": "Configuración CORS",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudo analizar CORS.",
            "evidence": str(exc),
            "recommendation": "Verificar conectividad."
        })

    return results