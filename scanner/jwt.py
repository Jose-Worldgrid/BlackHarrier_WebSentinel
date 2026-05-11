import base64
import json
from scanner.http_client import HttpClient


def decode_jwt_part(part):
    padding = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + padding).decode())


def scan_jwt_from_pages(pages):
    results = []

    possible_tokens = []

    for page in pages:
        html = page.get("html") or page.get("rendered_html") or ""
        page_url = page.get("url") or page.get("final_url") or ""
        if not html:
            continue

        for token in html.replace('"', " ").replace("'", " ").split():
            if token.count(".") == 2 and len(token) > 40:
                possible_tokens.append((page_url, token.strip()))

    for source_url, token in possible_tokens[:20]:
        try:
            header_part, payload_part, _ = token.split(".")
            header = decode_jwt_part(header_part)
            payload = decode_jwt_part(payload_part)

            alg = header.get("alg")
            issues = []

            if str(alg).lower() == "none":
                issues.append("Algoritmo 'none' detectado")

            if "exp" not in payload:
                issues.append("Token sin expiración exp")

            if issues:
                results.append({
                    "control": "JWT expuesto o débil",
                    "status": "Hallazgo",
                    "severity": "Alta",
                    "description": "Se detectó un JWT con configuración potencialmente insegura.",
                    "evidence": f"Página: {source_url} | Alg: {alg} | Issues: {', '.join(issues)}",
                    "recommendation": "Usar algoritmos robustos, expiración corta, rotación de claves y evitar exposición en HTML."
                })

        except Exception:
            continue

    if not results:
        results.append({
            "control": "JWT",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron JWT débiles o expuestos en HTML analizado.",
            "evidence": "Sin JWT vulnerables identificados.",
            "recommendation": "Revisar tokens en cookies, localStorage y flujos autenticados."
        })

    return results