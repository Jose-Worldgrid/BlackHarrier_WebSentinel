from urllib.parse import urljoin

from scanner.http_client import HttpClient


USER_HINTS = ["user", "username", "email", "login", "identifier", "usuario", "correo"]
PASS_HINTS = ["pass", "password", "pwd", "contraseña"]
SUCCESS_MARKERS = ["dashboard", "perfil", "mi cuenta", "close session", "logout", "sign out"]
FAILURE_MARKERS = ["invalid", "incorrect", "credenciales", "unauthorized", "denied", "error"]


def _normalize_url(value):
    return str(value or "").strip()


def _extract_auth_forms(pages):
    forms = []
    for page in pages or []:
        url = _normalize_url(page.get("final_url") or page.get("url"))
        if not url:
            continue

        classification = str(page.get("classification") or "").lower()
        page_forms = page.get("forms") or []
        for form in page_forms:
            if not isinstance(form, dict):
                continue

            method = str(form.get("method") or "POST").upper()
            action = form.get("action") or url
            fields = form.get("fields") or []

            has_user = any(
                any(token in str(field.get("name", "")).lower() for token in USER_HINTS)
                for field in fields
            )
            has_pass = any(
                str(field.get("type", "")).lower() == "password"
                or any(token in str(field.get("name", "")).lower() for token in PASS_HINTS)
                for field in fields
            )

            if classification in ["auth", "protected_redirect_to_auth"] or (has_user and has_pass):
                forms.append(
                    {
                        "page_url": url,
                        "action": urljoin(url, str(action)),
                        "method": method,
                        "fields": fields,
                    }
                )

    dedup = []
    seen = set()
    for form in forms:
        key = f"{form['method']}::{form['action']}"
        if key in seen:
            continue
        seen.add(key)
        dedup.append(form)
    return dedup


def _build_payload(fields, candidate_user, fixed_password):
    data = {}
    user_field = ""

    for field in fields:
        name = str(field.get("name") or "").strip()
        if not name:
            continue

        lower_name = name.lower()
        default_value = str(field.get("value") or "")

        if any(token in lower_name for token in USER_HINTS):
            data[name] = candidate_user
            if not user_field:
                user_field = name
        elif any(token in lower_name for token in PASS_HINTS):
            data[name] = fixed_password
        else:
            data[name] = default_value

    return data, user_field


def _response_signature(response):
    text = (response.text or "")
    lower = text.lower()

    return {
        "status": int(getattr(response, "status_code", 0) or 0),
        "length": len(text),
        "final_url": str(getattr(response, "url", "") or ""),
        "has_success_marker": any(marker in lower for marker in SUCCESS_MARKERS),
        "has_failure_marker": any(marker in lower for marker in FAILURE_MARKERS),
    }


def _score_difference(baseline, sample):
    score = 0.0
    if baseline["status"] != sample["status"]:
        score += 0.4
    if baseline["final_url"] != sample["final_url"]:
        score += 0.35

    max_len = max(1, baseline["length"])
    rel_diff = abs(sample["length"] - baseline["length"]) / max_len
    if rel_diff > 0.15:
        score += 0.2

    if baseline["has_failure_marker"] != sample["has_failure_marker"]:
        score += 0.2
    if sample["has_success_marker"] and not baseline["has_success_marker"]:
        score += 0.35

    return min(score, 0.99)


def scan_user_enumeration(pages, client=None, username_hint=""):
    """Low-noise username enumeration by response-difference analysis (authorized audits only)."""
    client = client or HttpClient()
    forms = _extract_auth_forms(pages)

    if not forms:
        return [
            {
                "control": "Enumeración de usuarios",
                "status": "No probado",
                "severity": "Informativa",
                "description": "No se detectaron formularios de autenticación aptos para enumeración segura.",
                "evidence": "Sin endpoints/formularios auth detectados en el alcance actual.",
                "recommendation": "Ejecutar con mayor superficie discovery o validar login dinámico con Playwright.",
            }
        ]

    candidates = []
    if username_hint:
        candidates.append(str(username_hint).strip())
    candidates.extend(["admin", "administrator", "test.user"])
    candidates = [c for c in list(dict.fromkeys(candidates)) if c]

    fixed_password = "Invalid-Password-For-Enum-Only-!2026"
    findings = []

    for form in forms[:5]:
        method = form["method"]
        action = form["action"]
        fields = form["fields"]

        baseline_user = "nonexistent.user.2026"
        baseline_data, user_field = _build_payload(fields, baseline_user, fixed_password)
        if not user_field:
            continue

        try:
            if method == "GET":
                baseline_resp = client.get(action, params=baseline_data)
            else:
                baseline_resp = client.post(action, data=baseline_data)
            baseline_sig = _response_signature(baseline_resp)
        except Exception as exc:
            findings.append(
                {
                    "control": f"Enumeración de usuarios en {action}",
                    "status": "Error",
                    "severity": "Baja",
                    "description": "No se pudo obtener baseline de respuesta para enumeración segura.",
                    "evidence": str(exc),
                    "recommendation": "Validar conectividad, WAF y parámetros esperados del endpoint.",
                }
            )
            continue

        suspicious = []
        for candidate in candidates[:3]:
            candidate_data, _ = _build_payload(fields, candidate, fixed_password)
            try:
                if method == "GET":
                    sample_resp = client.get(action, params=candidate_data)
                else:
                    sample_resp = client.post(action, data=candidate_data)
                sample_sig = _response_signature(sample_resp)
                diff = _score_difference(baseline_sig, sample_sig)
                if diff >= 0.5:
                    suspicious.append((candidate, diff, sample_sig))
            except Exception:
                continue

        if suspicious:
            top = sorted(suspicious, key=lambda item: item[1], reverse=True)[0]
            findings.append(
                {
                    "control": f"Enumeración de usuarios en {action}",
                    "status": "Posible hallazgo",
                    "severity": "Media",
                    "description": "Se observaron respuestas diferenciadas por nombre de usuario con contraseña fija inválida.",
                    "evidence": (
                        f"Campo usuario: {user_field} | Candidato: {top[0]} | Score diferencia: {top[1]:.2f} | "
                        f"Baseline(status={baseline_sig['status']},len={baseline_sig['length']}) vs "
                        f"Sample(status={top[2]['status']},len={top[2]['length']})"
                    ),
                    "recommendation": "Unificar mensajes/tiempos de error y aplicar rate limiting + lockout seguro.",
                }
            )
        else:
            findings.append(
                {
                    "control": f"Enumeración de usuarios en {action}",
                    "status": "No evidenciado",
                    "severity": "Informativa",
                    "description": "No se detectaron diferencias claras de respuesta para los candidatos evaluados.",
                    "evidence": f"Candidatos probados: {', '.join(candidates[:3])} | Campo usuario: {user_field}",
                    "recommendation": "Mantener respuestas uniformes y monitorizar intentos repetitivos.",
                }
            )

    return findings or [
        {
            "control": "Enumeración de usuarios",
            "status": "No probado",
            "severity": "Informativa",
            "description": "Se detectaron formularios auth, pero no se localizaron campos de usuario compatibles.",
            "evidence": f"Formularios analizados: {len(forms)}",
            "recommendation": "Revisar formularios dinámicos/API con instrumentación de navegador.",
        }
    ]
