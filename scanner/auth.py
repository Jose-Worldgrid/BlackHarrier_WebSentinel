from bs4 import BeautifulSoup
from urllib.parse import urljoin
from scanner.http_client import HttpClient


USERNAME_HINTS = ["user", "username", "email", "login"]
PASSWORD_HINTS = ["pass", "password", "pwd"]


def authenticate(login_url: str, username: str, password: str):
    client = HttpClient()

    if not username or not password:
        return client, [{
            "control": "Autenticación",
            "status": "No configurado",
            "severity": "Informativa",
            "description": "No se introdujeron credenciales.",
            "evidence": "Escaneo ejecutado sin sesión autenticada.",
            "recommendation": "Introducir credenciales para ampliar cobertura si existe login."
        }]

    results = []

    try:
        response = client.get(login_url)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return client, [{
                "control": "Autenticación",
                "status": "Error",
                "severity": "Media",
                "description": "No se detectó formulario de login en la URL indicada.",
                "evidence": login_url,
                "recommendation": "Verificar URL de login."
            }]

        form = forms[0]
        action = urljoin(login_url, form.get("action") or login_url)
        method = (form.get("method") or "POST").upper()

        data = {}

        for field in form.find_all(["input", "textarea"]):
            name = field.get("name")
            if not name:
                continue

            lower = name.lower()
            value = field.get("value") or ""

            if any(h in lower for h in USERNAME_HINTS):
                data[name] = username
            elif any(h in lower for h in PASSWORD_HINTS):
                data[name] = password
            else:
                data[name] = value

        if method == "POST":
            login_response = client.post(action, data=data)
        else:
            login_response = client.get(action, params=data)

        body = login_response.text.lower()

        success_markers = ["logout", "cerrar sesión", "cerrar sesion", "dashboard", "perfil", "mi cuenta"]
        failed_markers = ["incorrect", "invalid", "credenciales", "error", "denied", "unauthorized"]

        if any(x in body for x in success_markers):
            status = "Autenticado"
            severity = "Informativa"
            description = "Inicio de sesión aparentemente correcto."
        elif any(x in body for x in failed_markers):
            status = "Fallido"
            severity = "Media"
            description = "El inicio de sesión parece haber fallado."
        else:
            status = "Indeterminado"
            severity = "Baja"
            description = "No se pudo confirmar de forma concluyente el estado de autenticación."

        results.append({
            "control": "Autenticación",
            "status": status,
            "severity": severity,
            "description": description,
            "evidence": f"Login URL: {login_url} | Final URL: {login_response.url} | Status: {login_response.status_code}",
            "recommendation": "Validar manualmente si la sesión autenticada quedó establecida."
        })

    except Exception as exc:
        results.append({
            "control": "Autenticación",
            "status": "Error",
            "severity": "Media",
            "description": "Error durante el intento de autenticación.",
            "evidence": str(exc),
            "recommendation": "Revisar URL, campos del formulario y credenciales."
        })

    return client, results