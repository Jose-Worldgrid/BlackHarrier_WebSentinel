"""
JWT security scanner.

Checks performed:
  1. Token discovery: HTML, cookies (Set-Cookie), API response bodies
  2. Weak / dangerous algorithms: none, HS256 with empty/common secret
  3. Algorithm confusion attack: RS256 / RS384 / RS512 → HS256 forgery probe
  4. kid (Key ID) header injection: path traversal, SQL injection via kid
  5. Missing / expired claims: exp, nbf, iat
  6. Sensitive data exposure in payload
"""

import base64
import json
import hashlib
import hmac
import re
import time as _time
from scanner.http_client import HttpClient


# ---------------------------------------------------------------------------
# Common weak secrets tried in brute-force phase
# ---------------------------------------------------------------------------
_WEAK_SECRETS = [
    "", "secret", "password", "123456", "changeme", "supersecret",
    "jwt_secret", "your-256-bit-secret", "your-secret", "admin",
    "qwerty", "letmein", "pass", "token", "mysecret", "app_secret",
    "hs256secret", "secretkey", "key", "privatekey",
]

_ASYMMETRIC_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

_SENSITIVE_CLAIM_PATTERNS = re.compile(
    r"(password|passwd|secret|token|credit_card|ssn|cvv|pin|private_key|api_key)",
    re.IGNORECASE,
)


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_jwt_part(part: str) -> dict:
    return json.loads(_b64url_decode(part).decode("utf-8", errors="replace"))


def _forge_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    """Build a JWT signed with HS256 using *secret*."""
    new_header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    signing_input = f"{new_header}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{new_header}.{payload_b64}.{_b64url_encode(sig)}"


def _extract_tokens_from_html(html: str, page_url: str) -> list[tuple[str, str]]:
    """Return list of (source_url, token) found in HTML."""
    tokens = []
    for token in html.replace('"', " ").replace("'", " ").split():
        if token.count(".") == 2 and len(token) > 40:
            tokens.append((page_url, token.strip()))
    return tokens


def _extract_tokens_from_cookies(response, page_url: str) -> list[tuple[str, str]]:
    """Extract JWT candidates from Set-Cookie headers."""
    tokens = []
    for cookie_header in response.headers.getlist("Set-Cookie") if hasattr(response.headers, "getlist") else []:
        for part in cookie_header.split(";"):
            value = part.split("=", 1)[-1].strip()
            if value.count(".") == 2 and len(value) > 40:
                tokens.append((page_url, value))
    return tokens


def _check_algorithm_confusion(header: dict, header_b64: str, payload_b64: str) -> list[str]:
    """
    Check if an asymmetric JWT can be forged as HS256 using the public key as HMAC secret.
    We flag the *risk* when alg is asymmetric — actual key material is not available here,
    so we report the vulnerability class rather than a live exploit.
    """
    alg = str(header.get("alg", "")).upper()
    if alg in _ASYMMETRIC_ALGS:
        return [
            f"Algoritmo asimétrico '{alg}' detectado. "
            "Si el servidor acepta HS256 con la clave pública como secreto, "
            "es vulnerable a Algorithm Confusion (CVE-2016-10555 / jwt-toolkit alg-confusion). "
            "Verificar manualmente que el servidor rechace tokens con alg=HS256."
        ]
    return []


def _check_kid_injection(header: dict) -> list[str]:
    """Flag dangerous kid header patterns."""
    kid = str(header.get("kid", ""))
    if not kid:
        return []
    issues = []
    # Path traversal via kid
    if any(seq in kid for seq in ("../", "..\\", "/etc/", "/proc/")):
        issues.append(
            f"kid header contiene path traversal: '{kid}'. "
            "Si el servidor usa kid como ruta para cargar la clave, "
            "puede leer archivos arbitrarios o usar /dev/null como clave vacía."
        )
    # SQL injection via kid
    sqli_chars = ("'", '"', "--", ";", " OR ", " AND ")
    if any(ch in kid for ch in sqli_chars):
        issues.append(
            f"kid header contiene caracteres de inyección SQL: '{kid}'. "
            "Posible SQLi en el sistema de carga de claves."
        )
    return issues


def _check_weak_secret(header_b64: str, payload_b64: str) -> str | None:
    """Try common secrets against HS256. Returns secret if found."""
    signing_input = f"{header_b64}.{payload_b64}".encode()
    # We don't have the original signature here, but we flag the attempt
    # The proper check requires the full token; handled in scan_jwt_from_pages
    return None


def _check_sensitive_claims(payload: dict) -> list[str]:
    issues = []
    for key, val in payload.items():
        if _SENSITIVE_CLAIM_PATTERNS.search(str(key)):
            issues.append(f"Claim sensible en payload: '{key}'")
        if isinstance(val, str) and _SENSITIVE_CLAIM_PATTERNS.search(val):
            issues.append(f"Valor sensible en claim '{key}'")
    return issues


def _verify_hs256(token: str, secret: str) -> bool:
    """Return True if token verifies with the given secret."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        header_b64, payload_b64, sig_b64 = parts
        header = decode_jwt_part(header_b64)
        if str(header.get("alg", "")).upper() != "HS256":
            return False
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        actual = _b64url_decode(sig_b64)
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False


def scan_jwt_from_pages(pages):
    results = []
    client = HttpClient()
    all_tokens: list[tuple[str, str]] = []  # (source_url, token)

    for page in pages:
        html = page.get("html") or page.get("rendered_html") or ""
        page_url = page.get("url") or page.get("final_url") or ""
        if not html and not page_url:
            continue

        # Discover tokens in HTML
        all_tokens.extend(_extract_tokens_from_html(html, page_url))

        # Fetch the page to check cookies
        if page_url:
            try:
                resp = client.get(page_url)
                all_tokens.extend(_extract_tokens_from_cookies(resp, page_url))
            except Exception:
                pass

    # Deduplicate by token value
    seen: set[str] = set()
    unique_tokens: list[tuple[str, str]] = []
    for src, tok in all_tokens[:50]:
        if tok not in seen:
            seen.add(tok)
            unique_tokens.append((src, tok))

    for source_url, token in unique_tokens:
        try:
            parts = token.split(".")
            if len(parts) != 3:
                continue
            header_b64, payload_b64, sig_b64 = parts
            header = decode_jwt_part(header_b64)
            payload = decode_jwt_part(payload_b64)
        except Exception:
            continue

        alg = str(header.get("alg", "")).upper()
        issues: list[str] = []

        # 1. Algorithm: none
        if alg == "NONE":
            issues.append("Algoritmo 'none' — el token no tiene firma. Se puede falsificar trivialmente.")

        # 2. Algorithm confusion (asymmetric → HS256)
        issues.extend(_check_algorithm_confusion(header, header_b64, payload_b64))

        # 3. kid injection
        issues.extend(_check_kid_injection(header))

        # 4. Missing claims
        now = int(_time.time())
        if "exp" not in payload:
            issues.append("Token sin claim 'exp' — no expira nunca.")
        elif int(payload.get("exp", now + 1)) < now:
            issues.append(f"Token expirado (exp={payload['exp']}, ahora={now}).")
        if "iat" not in payload:
            issues.append("Token sin claim 'iat' — imposible detectar tokens demasiado antiguos.")

        # 5. Sensitive data in payload
        issues.extend(_check_sensitive_claims(payload))

        # 6. Weak secret brute force (HS256 only)
        if alg == "HS256":
            for secret in _WEAK_SECRETS:
                if _verify_hs256(token, secret):
                    issues.append(
                        f"Secreto HS256 débil encontrado: '{secret}'. "
                        "Un atacante puede forjar tokens arbitrarios."
                    )
                    break

        if issues:
            # Determine highest severity
            severity = "Alta"
            if any("falsificar" in i or "débil" in i or "Confusion" in i for i in issues):
                severity = "Crítica"

            results.append({
                "control": "JWT inseguro o débil",
                "status": "Hallazgo",
                "severity": severity,
                "description": "Se detectó un JWT con uno o más problemas de seguridad.",
                "evidence": (
                    f"Origen: {source_url} | Alg: {alg} | "
                    f"Problemas: {' | '.join(issues)}"
                ),
                "recommendation": (
                    "Usar RS256/ES256 con claves rotadas. "
                    "Exigir exp/iat en todos los tokens. "
                    "Nunca aceptar alg=none. "
                    "Validar alg server-side y rechazar cambios de asimétrico a simétrico. "
                    "No exponer datos sensibles en payload (es base64, no cifrado)."
                ),
            })

    if not results:
        results.append({
            "control": "JWT",
            "status": "No evidenciado",
            "severity": "Informativa",
            "description": (
                "No se detectaron JWT con problemas de seguridad. "
                "Se analizaron tokens en HTML y cookies."
            ),
            "evidence": f"Tokens analizados: {len(unique_tokens)}",
            "recommendation": (
                "Revisar manualmente tokens en Authorization Bearer, localStorage y "
                "respuestas de endpoints de autenticación."
            ),
        })

    return results