# BlackHarrier WebAudit Toolkit

Plataforma de auditoria web ofensiva autorizada, con orquestacion de recon, pruebas de seguridad y analisis asistido por IA.

## Aviso legal

Uso exclusivo en entornos propios o con autorizacion expresa y verificable.

## Capacidades principales

- Reconocimiento web y descubrimiento de superficie (crawler + discovery activo).
- Reconocimiento de red y servicios (Nmap + correlacion de vulnerabilidades).
- Correlacion de CVE y contexto de explotabilidad.
- Planificacion ofensiva adaptativa con control de falsos positivos.
- Agente IA con Azure OpenAI por defecto.
- Generacion de informe tecnico en formato Word.

## Requisitos

- Python 3.10+
- Nmap (recomendado)
- Windows PowerShell 5.1+ para setup.ps1 en Windows

## Instalacion rapida (Windows)

```powershell
git clone https://github.com/TU_USUARIO/blackharrier-webaudit.git
cd blackharrier-webaudit
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

Luego:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

## Configuracion IA (Azure OpenAI)

1. Copia el archivo de ejemplo:

```powershell
Copy-Item .env.example .env
```

2. Edita .env y completa:

- AZURE_OPENAI_ENDPOINT
- AZURE_OPENAI_API_KEY
- AZURE_OPENAI_MINI_DEPLOYMENT
- AZURE_OPENAI_MINI_API_VERSION

3. Reinicia la app.

## Variables de entorno soportadas

- AZURE_OPENAI_ENDPOINT
- AZURE_OPENAI_API_KEY
- AZURE_OPENAI_MINI_DEPLOYMENT
- AZURE_OPENAI_MINI_API_VERSION
- AZURE_OPENAI_API_VERSION
- AI_AGENT_LLM_PROVIDER (default: azure_openai)

## Flujo recomendado

1. Definir objetivo autorizado.
2. Ejecutar Fase 1 (recon + correlacion).
3. Revisar plan IA ofensivo.
4. Ejecutar Fase 2 controlada.
5. Revisar evidencias y generar informe.

## Estructura de proyecto (resumen)

- app.py: orquestador principal Streamlit.
- config.py: configuracion global y carga de .env.
- scanner/: modulos de escaneo, IA y correlacion.
- reports/: generacion de informes.
- setup.ps1: instalacion y verificacion en Windows.

## Buenas practicas de repositorio

- No subir resultados de auditoria.
- No subir credenciales o llaves.
- Mantener .env fuera de control de versiones.

## Licencia

MIT.
