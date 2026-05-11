from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanner.http_client import HttpClient


SSRF_PARAM_HINTS = [
    "url", "uri", "endpoint", "target", "dest", "destination",
    "callback", "webhook", "image", "file", "path", "proxy", "redirect",
    "src", "source", "link", "host", "domain", "server", "api", "feed",
    "import", "export", "resource", "location"
]

# Cloud metadata + internal probes ordered by likelihood
SSRF_PROBE_TARGETS = [
    # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Loopback
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://localhost/",
    # Internal ranges
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    # External baseline (must NOT produce internal content)
    "https://example.org/",
]

SSRF_INTERNAL_SIGNATURES = [
    # AWS
    "ami-id", "instance-id", "security-credentials", "iam",
    # GCP
    "computeMetadata", "serviceAccounts",
    # Azure
    "azEnvironment", "resourceGroupName",
    # Generic
    "127.0.0.1", "localhost", "internal",
]


def _probe_ssrf(client, base_url, param, params, probe):
    mutated = params.copy()
    mutated[param] = probe
    test_url = urlunparse(urlparse(base_url)._replace(query=urlencode(mutated, doseq=True)))
    try:
        r = client.get(test_url, timeout=6, allow_redirects=False)
        return r, test_url
    except Exception:
        return None, test_url


def scan_ssrf_hints(pages):
    client = HttpClient()
    results = []

    for page in pages:
        page_url = page.get("url") or page.get("final_url") or ""
        if not page_url:
            continue
        parsed = urlparse(page_url)
        params = parse_qs(parsed.query)

        if not params:
            continue

        for param in list(params.keys()):
            if param.lower() not in SSRF_PARAM_HINTS:
                continue

            try:
                original = client.get(page_url)
            except Exception:
                continue

            for probe in SSRF_PROBE_TARGETS:
                r, test_url = _probe_ssrf(client, page_url, param, params, probe)
                if r is None:
                    continue

                body = r.text or ""
                has_internal_content = any(sig.lower() in body.lower() for sig in SSRF_INTERNAL_SIGNATURES)
                is_differential = (
                    r.status_code != original.status_code
                    or abs(len(body) - len(original.text or "")) > 400
                )

                if has_internal_content:
                    results.append({
                        "control": f"SSRF confirmado: {param} → metadatos internos",
                        "status": "Hallazgo",
                        "severity": "Crítica",
                        "description": "La respuesta contiene indicadores de metadatos de nube o servicios internos.",
                        "evidence": f"URL: {test_url} | Probe: {probe} | Firmas detectadas",
                        "recommendation": "Bloquear acceso a rangos privados/metadatos en el servidor. Aplicar allowlist estricta de destinos."
                    })
                    break
                elif is_differential and "example.org" not in probe:
                    results.append({
                        "control": f"SSRF diferencial: {param}",
                        "status": "Posible hallazgo",
                        "severity": "Alta",
                        "description": "Parámetro produce respuesta diferencial al apuntar a IP interna.",
                        "evidence": f"URL: {test_url} | Probe: {probe} | Status orig: {original.status_code} | Status prueba: {r.status_code}",
                        "recommendation": "Validar allowlist de destinos, bloquear IPs internas y deshabilitar fetch arbitrario server-side."
                    })
                    break

    if not results:
        results.append({
            "control": "SSRF",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": "No se detectaron parámetros candidatos a SSRF con respuesta diferencial o metadatos internos.",
            "evidence": "Sin indicios de SSRF activo.",
            "recommendation": "Complementar con revisión de código, Burp Collaborator y pruebas autenticadas."
        })

    return results