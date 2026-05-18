@echo off
setlocal EnableDelayedExpansion

echo ============================================================
echo  BlackHarrier WebAudit Toolkit - Setup (Windows)
echo ============================================================
echo.

:: ---------------------------------------------------------------------------
:: 1. Check Python 3.10+
:: ---------------------------------------------------------------------------
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python no encontrado en PATH.
    echo         Descarga Python 3.10+ desde https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo [OK] Python %PY_VER% detectado.

:: ---------------------------------------------------------------------------
:: 2. Create virtual environment (if it doesn't exist yet)
:: ---------------------------------------------------------------------------
if not exist ".venv\Scripts\activate.bat" (
    echo [*] Creando entorno virtual .venv ...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] No se pudo crear el entorno virtual.
        pause
        exit /b 1
    )
    echo [OK] Entorno virtual creado.
) else (
    echo [OK] Entorno virtual .venv ya existe.
)

call .venv\Scripts\activate.bat

:: ---------------------------------------------------------------------------
:: 3. Install Python dependencies
:: ---------------------------------------------------------------------------
echo [*] Instalando dependencias Python desde requirements.txt ...
pip install --upgrade pip --quiet
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Fallo al instalar dependencias.
    pause
    exit /b 1
)
echo [OK] Dependencias instaladas.

:: ---------------------------------------------------------------------------
:: 4. Install Playwright browser (Chromium)
:: ---------------------------------------------------------------------------
echo [*] Instalando navegador Chromium para Playwright ...
playwright install chromium
if %errorlevel% neq 0 (
    echo [WARN] Playwright install falló. Puedes ejecutarlo manualmente:
    echo        playwright install chromium
) else (
    echo [OK] Chromium instalado.
)

:: ---------------------------------------------------------------------------
:: 5. Check Nmap
:: ---------------------------------------------------------------------------
where nmap.exe >nul 2>&1
if %errorlevel% equ 0 (
    for /f "delims=" %%n in ('nmap.exe --version 2^>^&1 ^| findstr /i "Nmap version"') do set NMAP_VER=%%n
    echo [OK] Nmap detectado: !NMAP_VER!
) else (
    echo.
    echo [AVISO] Nmap no detectado en PATH.
    echo         Para habilitar el reconocimiento de red, descarga e instala Nmap:
    echo         https://nmap.org/download.html#windows
    echo         Asegurate de marcar "Add Nmap to PATH" durante la instalacion.
    echo         Tras la instalacion, reinicia este script o la herramienta.
    echo.
)

:: ---------------------------------------------------------------------------
:: 6. Check Ollama (optional – AI exploit suggester)
:: ---------------------------------------------------------------------------
where ollama.exe >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Ollama detectado - el agente de exploits puede usar modelos locales.
) else (
    echo [INFO] Ollama no encontrado (opcional).
    echo        Para habilitar el agente IA de exploits con modelos locales:
    echo        https://ollama.com/download
    echo        Tras instalarlo: ollama pull llama3
    echo.
)

:: ---------------------------------------------------------------------------
:: 7. Create storage directories
:: ---------------------------------------------------------------------------
if not exist "storage" mkdir storage
if not exist "reports\output" mkdir reports\output
echo [OK] Directorios de almacenamiento listos.

:: ---------------------------------------------------------------------------
:: Done
:: ---------------------------------------------------------------------------
echo.
echo ============================================================
echo  Instalacion completada.
echo  Para iniciar BlackHarrier:
echo    .venv\Scripts\activate.bat
echo    streamlit run app.py
echo ============================================================
echo.
pause
