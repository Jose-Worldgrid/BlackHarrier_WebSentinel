from bs4 import BeautifulSoup
from scanner.http_client import HttpClient


def scan_recon(url: str):
    client = HttpClient()
    results = []

    try:
        response = client.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        server = response.headers.get("Server", "No expuesto")
        powered_by = response.headers.get("X-Powered-By", "No expuesto")
        generator = soup.find("meta", attrs={"name": "generator"})

        tech_evidence = [
            f"Server: {server}",
            f"X-Powered-By: {powered_by}",
        ]

        if generator:
            tech_evidence.append(f"Meta generator: {generator.get('content')}")

        scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
        if scripts:
            tech_evidence.append(f"Scripts detectados: {', '.join(scripts[:10])}")

        results.append({
            "control": "Fingerprinting tecnológico",
            "status": "Detectado",
            "severity": "Baja" if server != "No expuesto" or powered_by != "No expuesto" else "Informativa",
            "description": "Se recopila información técnica expuesta por la aplicación.",
            "evidence": " | ".join(tech_evidence),
            "recommendation": "Reducir banners tecnológicos, ocultar versiones y minimizar exposición de stack."
        })

    except Exception as exc:
        results.append({
            "control": "Fingerprinting tecnológico",
            "status": "Error",
            "severity": "Media",
            "description": "No se pudo ejecutar reconocimiento tecnológico.",
            "evidence": str(exc),
            "recommendation": "Verificar conectividad."
        })

    return results