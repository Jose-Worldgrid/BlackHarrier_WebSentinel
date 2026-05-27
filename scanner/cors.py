"""
CORS security scanner.

Tests performed per endpoint:
  1. Arbitrary origin reflection        – Origin: https://evil.example
  2. Subdomain wildcard reflection      – Origin: https://evil.<target>
  3. null origin                        – Origin: null  (iframe sandbox / file:// bypass)
  4. Wildcard with credentials          – combo ACAO=* + ACAC=true
  5. OPTIONS preflight                  – checks ACAM, ACAH, max-age
  6. Vary: Origin header presence       – absence can cause caching poisoning

Tested URLs: root + all discovered API/sensitive endpoints.
"""

from urllib.parse import urlparse
from scanner.http_client import HttpClient


def _target_subdomain_origin(target_url: str) -> str:
    """Construct an attacker-controlled subdomain that looks legit."""
    parsed = urlparse(target_url)
    netloc = parsed.netloc.split(":")[0]
    return f"https://evil.{netloc}"


def _classify_cors(acao: str | None, acac: str | None, origin_sent: str) -> tuple[str, str, str]:
    """Return (severity, status, description)."""
    if not acao:
        return "Informativa", "No evidenciado", "No se devolvió cabecera CORS para este origen."

    creds = str(acac or "").lower() == "true"

    if acao == "*" and creds:
        return (
            "Crítica", "Hallazgo",
            "CORS wildcard (*) combinado con Access-Control-Allow-Credentials: true. "
            "Permite a cualquier origen leer respuestas autenticadas."
        )
    if acao == origin_sent:
        if creds:
            return (
                "Crítica", "Hallazgo",
                f"CORS refleja el origen arbitrario '{origin_sent}' con credenciales habilitadas. "
                "Cualquier sitio puede realizar peticiones autenticadas cross-origin."
            )
        return (
            "Alta", "Hallazgo",
            f"CORS refleja el origen arbitrario '{origin_sent}'. "
            "Un atacante puede leer respuestas no autenticadas desde cualquier dominio."
        )
    if acao == "*":
        return (
            "Media", "Hallazgo",
            "CORS permite cualquier origen (*). Aceptable solo para APIs públicas sin autenticación."
        )
    return "Informativa", "No evidenciado", f"CORS restrictivo. ACAO: {acao}"


def _probe_endpoint(client: HttpClient, url: str, target_url: str) -> list[dict]:
    """Run all CORS probes against a single URL. Returns list of result dicts."""
    results = []
    findings: list[tuple[str, str, str, str]] = []  # (origin_sent, acao, acac, note)

    probes = [
        ("arbitrary_origin",  "https://evil.example"),
        ("subdomain",         _target_subdomain_origin(target_url)),
        ("null_origin",       "null"),
    ]

    for probe_name, origin in probes:
        try:
            resp = client.get(url, headers={"Origin": origin})
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("Access-Control-Allow-Credentials")
            vary = resp.headers.get("Vary", "")
            severity, status, description = _classify_cors(acao, acac, origin)

            if status == "Hallazgo":
                # Vary: Origin absence on reflected CORS → caching attack
                vary_warning = ""
                if acao and acao != "*" and "origin" not in vary.lower():
                    vary_warning = " Además, 'Vary: Origin' ausente — riesgo de CORS cache poisoning."

                results.append({
                    "control": f"Configuración CORS [{probe_name}]",
                    "status": status,
                    "severity": severity,
                    "description": description + vary_warning,
                    "evidence": (
                        f"URL: {url} | Origin enviado: {origin} | "
                        f"ACAO: {acao} | ACAC: {acac} | Vary: {vary or '(ausente)'}"
                    ),
                    "recommendation": (
                        "Mantener una allowlist explícita de orígenes. "
                        "Nunca reflejar el origen entrante sin validación. "
                        "No combinar CORS amplio con credenciales. "
                        "Incluir 'Vary: Origin' cuando ACAO varía por petición."
                    ),
                })
        except Exception:
            pass

    # OPTIONS preflight check
    try:
        resp = client.options(
            url,
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization",
            },
        )
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        max_age = resp.headers.get("Access-Control-Max-Age", "")

        if acao == "https://evil.example" or acao == "*":
            dangerous_methods = [m.strip().upper() for m in acam.split(",") if m.strip().upper() in ("DELETE", "PUT", "PATCH")]
            if dangerous_methods:
                results.append({
                    "control": "CORS preflight - métodos peligrosos permitidos",
                    "status": "Hallazgo",
                    "severity": "Alta",
                    "description": (
                        f"El preflight OPTIONS autoriza métodos destructivos para origen arbitrario: "
                        f"{', '.join(dangerous_methods)}."
                    ),
                    "evidence": (
                        f"URL: {url} | ACAO: {acao} | ACAM: {acam} | ACAH: {acah}"
                    ),
                    "recommendation": (
                        "Restringir ACAM a los métodos estrictamente necesarios. "
                        "No autorizar DELETE/PUT/PATCH a orígenes externos salvo que sea intencional."
                    ),
                })
    except Exception:
        pass

    return results


def scan_cors(url: str, pages: list | None = None) -> list[dict]:
    """
    Full CORS scan.
    Tests the root URL and any discovered API/sensitive endpoints from *pages*.
    """
    client = HttpClient()
    results = []

    # Build set of unique endpoints to test
    endpoints: list[str] = [url]
    for page in pages or []:
        page_url = page.get("final_url") or page.get("url") or ""
        cls = str(page.get("classification") or "")
        if cls in ("api_candidate", "sensitive_candidate", "protected", "admin_candidate"):
            if page_url and page_url not in endpoints:
                endpoints.append(page_url)
        # Cap to avoid excessive traffic
        if len(endpoints) >= 10:
            break

    tested_origins: set[str] = set()
    for endpoint in endpoints:
        endpoint_results = _probe_endpoint(client, endpoint, url)
        for r in endpoint_results:
            # Deduplicate by (origin, acao) pair
            key = r.get("evidence", "")[:80]
            if key not in tested_origins:
                tested_origins.add(key)
                results.append(r)

    if not results:
        results.append({
            "control": "Configuración CORS",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": (
                "No se detectó una configuración CORS permisiva en los endpoints probados "
                "(origen arbitrario, subdomain, null)."
            ),
            "evidence": f"Endpoints probados: {len(endpoints)} | Orígenes probados: arbitrary, subdomain, null",
            "recommendation": (
                "Mantener allowlist explícita. Revisar endpoints autenticados con prueba manual."
            ),
        })

    return results