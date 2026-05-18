#!/usr/bin/env bash
# BlackHarrier WebAudit Toolkit - Setup (Linux / macOS)
set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[AVISO]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

echo "============================================================"
echo "  BlackHarrier WebAudit Toolkit - Setup (Unix)"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# 1. Check Python 3.10+
# ---------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
    error "Python3 no encontrado. Instala Python 3.10+ con tu gestor de paquetes."
fi
PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
MAJOR=$(echo "$PY_VER" | cut -d. -f1)
MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$MAJOR" -lt 3 ] || { [ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]; }; then
    error "Se requiere Python 3.10+. Versión detectada: $PY_VER"
fi
ok "Python $PY_VER detectado."

# ---------------------------------------------------------------------------
# 2. Virtual environment
# ---------------------------------------------------------------------------
if [ ! -f ".venv/bin/activate" ]; then
    info "Creando entorno virtual .venv ..."
    python3 -m venv .venv
    ok "Entorno virtual creado."
else
    ok "Entorno virtual .venv ya existe."
fi

# shellcheck source=/dev/null
source .venv/bin/activate

# ---------------------------------------------------------------------------
# 3. Python dependencies
# ---------------------------------------------------------------------------
info "Actualizando pip e instalando dependencias ..."
pip install --upgrade pip --quiet
pip install -r requirements.txt
ok "Dependencias instaladas."

# ---------------------------------------------------------------------------
# 4. Playwright – Chromium
# ---------------------------------------------------------------------------
info "Instalando Chromium para Playwright ..."
if playwright install chromium; then
    ok "Chromium instalado."
else
    warn "Playwright install falló. Ejecuta manualmente: playwright install chromium"
fi

# ---------------------------------------------------------------------------
# 5. Nmap
# ---------------------------------------------------------------------------
if command -v nmap &>/dev/null; then
    ok "Nmap detectado: $(nmap --version | head -1)"
else
    warn "Nmap no encontrado."
    echo ""
    echo "  Para instalarlo:"
    echo "    Ubuntu/Debian : sudo apt-get install -y nmap"
    echo "    Fedora/RHEL   : sudo dnf install -y nmap"
    echo "    macOS (brew)  : brew install nmap"
    echo "  Tras la instalacion reinicia la herramienta."
    echo ""
fi

# ---------------------------------------------------------------------------
# 6. Ollama (optional – AI exploit suggester)
# ---------------------------------------------------------------------------
if command -v ollama &>/dev/null; then
    ok "Ollama detectado - el agente IA de exploits puede usar modelos locales."
else
    echo ""
    info "Ollama no encontrado (opcional)."
    echo "  Para habilitar el agente IA de exploits con modelos locales:"
    echo "    https://ollama.com/download"
    echo "  Tras instalarlo: ollama pull llama3"
    echo ""
fi

# ---------------------------------------------------------------------------
# 7. Storage directories
# ---------------------------------------------------------------------------
mkdir -p storage reports/output
ok "Directorios de almacenamiento listos."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Instalacion completada."
echo "  Para iniciar BlackHarrier:"
echo "    source .venv/bin/activate"
echo "    streamlit run app.py"
echo "============================================================"
echo ""
