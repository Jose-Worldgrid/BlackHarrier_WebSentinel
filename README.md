# BlackHarrier WebAudit Toolkit

A modular, Streamlit-based web security auditing toolkit designed for authorized penetration testing and vulnerability assessments.

> ⚠️ **Uso ético y legal**: Esta herramienta está diseñada **exclusivamente** para pruebas en sistemas propios o con autorización expresa por escrito. El uso no autorizado puede ser ilegal. Los autores no se responsabilizan del mal uso.

---

## Características principales

| Módulo | Descripción |
|---|---|
| **Descubrimiento** | Crawling de rutas, detección de formularios, endpoints de auth |
| **Reconocimiento Nmap** | Escaneo de puertos, detección de servicios y versiones, scripts NSE |
| **CVE Lookup** | Búsqueda automática de CVEs en NVD/Vulners para los servicios detectados |
| **Agente IA – Exploit Suggester** | Propone y genera PoC de exploits en base a los CVEs encontrados |
| **Análisis de autenticación** | Prueba de bypass, credenciales débiles, manejo de sesión |
| **Control de acceso / IDOR** | Pruebas de acceso horizontal/vertical, manipulación de IDs |
| **BlackHarrier Scanner** | Escáner propio: ports, SSL/TLS, DNS, fingerprinting de servicios |
| **Informes Word** | Generación automática de informes `.docx` con evidencias y recomendaciones |

---

## Requisitos del sistema

| Requisito | Versión mínima | Notas |
|---|---|---|
| Python | 3.10+ | [python.org](https://www.python.org/downloads/) |
| Nmap | 7.80+ | Opcional, recomendado para recon completo |
| Ollama | cualquiera | Opcional, para agente IA de exploits local |

---

## Instalación rápida

### Windows

```bat
git clone https://github.com/TU_USUARIO/blackharrier-webaudit.git
cd blackharrier-webaudit
setup_windows.bat
```

### Linux / macOS

```bash
git clone https://github.com/TU_USUARIO/blackharrier-webaudit.git
cd blackharrier-webaudit
chmod +x setup_unix.sh
./setup_unix.sh
```

Los scripts hacen automáticamente:
1. Crean un entorno virtual Python (`.venv`)
2. Instalan todas las dependencias de `requirements.txt`
3. Instalan Chromium para Playwright
4. Detectan Nmap y Ollama, con instrucciones si no están presentes

---

## Instalación manual

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
playwright install chromium
```

---

## Instalar Nmap (reconocimiento de red)

Nmap es **opcional pero recomendado**. La herramienta lo detecta automáticamente en PATH.

| Sistema | Comando |
|---|---|
| Windows | [Descarga el instalador](https://nmap.org/download.html#windows) – marca **"Add Nmap to PATH"** |
| Ubuntu/Debian | `sudo apt-get install -y nmap` |
| Fedora/RHEL | `sudo dnf install -y nmap` |
| macOS | `brew install nmap` |

> En Windows, Npcap (incluido con Nmap) requiere privilegios de administrador para raw sockets. Para escaneos `-sS` (SYN scan) ejecuta la herramienta como administrador o usa el perfil **SAFE** (que usa `-Pn -sV` sin raw sockets).

---

## Instalar Ollama (agente IA de exploits – opcional)

El módulo `ExploitSuggester` puede usar un modelo de lenguaje local para generar propuestas de exploits y código PoC directamente desde los CVEs encontrados.

1. Descarga Ollama: <https://ollama.com/download>
2. Instala un modelo:
   ```bash
   ollama pull llama3          # recomendado – buena relación velocidad/calidad
   # o
   ollama pull mistral         # alternativa ligera
   # o
   ollama pull codellama       # especializado en código
   ```
3. Reinicia la herramienta – el selector de modelo aparecerá automáticamente en la barra lateral.

Si Ollama no está disponible, el sugeridor de exploits funciona igualmente en **modo offline** generando plantillas estructuradas basadas en la base de datos interna de técnicas por servicio y severidad.

---

## Uso

```bash
# Activar entorno virtual
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/macOS

# Iniciar la herramienta
streamlit run app.py
```

Abre el navegador en `http://localhost:8501`.

### Flujo de trabajo típico

```
1. Introducir URL objetivo
2. Seleccionar modo de escaneo (Reconocimiento / Evaluación completa)
3. Activar Nmap si está disponible → elegir perfil (SAFE / DEEP / AGGRESSIVE)
4. Ejecutar escaneo → la herramienta recorre todas las fases
5. Revisar CVEs detectados → el agente IA propone exploits
6. Revisar evidencias en la pestaña de resultados
7. Generar informe Word
```

---

## Perfiles Nmap

| Perfil | Flags | Cuándo usarlo |
|---|---|---|
| **SAFE** | `-sV -Pn -T3` | Producción, entornos sensibles, sin raw sockets |
| **DEEP** | `-sV -sC -O -Pn` | Lab / staging, detección de OS y scripts básicos |
| **AGGRESSIVE** | `-sV -sC -A -O --script=vuln,http-enum` | Auditorías internas completas, más ruidoso |

---

## Estructura del proyecto

```
blackharrier-webaudit/
├── app.py                        # Orquestador principal (Streamlit)
├── config.py                     # Modos de escaneo y configuración global
├── requirements.txt
├── setup_windows.bat
├── setup_unix.sh
├── scanner/
│   ├── discovery.py              # Crawling y descubrimiento
│   ├── forms.py                  # Análisis de formularios
│   ├── auth.py                   # Pruebas de autenticación
│   ├── access_control.py         # Control de acceso / IDOR
│   ├── cve_lookup.py             # Búsqueda de CVEs (NVD + Vulners)
│   ├── exploit_suggester.py      # Agente IA – propuesta de exploits
│   ├── nmap_scanner.py           # Integración Nmap
│   ├── free_assessment.py        # BlackHarrier Scanner
│   ├── port_scanner.py           # Escáner de puertos (Python puro)
│   ├── ssl_analyzer.py           # Análisis SSL/TLS
│   ├── dns_scanner.py            # Enumeración DNS
│   ├── service_fingerprint.py    # Fingerprinting de servicios
│   └── ai_agent/
│       └── executor.py           # Executor del agente adaptativo
├── reports/
│   └── word_report.py            # Generación de informes Word
└── storage/
    └── cve_cache.json            # Caché de CVEs (24h TTL)
```

---

## Tests

```bash
.venv\Scripts\activate            # Windows
source .venv/bin/activate         # Linux/macOS

pytest tests/test_scanner_regressions.py -v
```

---

## Licencia

Este proyecto se distribuye bajo licencia **MIT**. Consulta el archivo `LICENSE` para más detalles.

---

## Contribuciones

Las contribuciones son bienvenidas. Abre un issue antes de enviar un PR para discutir los cambios propuestos.
