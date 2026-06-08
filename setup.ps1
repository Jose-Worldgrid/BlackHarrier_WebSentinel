$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[>] $Message" -ForegroundColor DarkRed
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor White
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Red
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Centered {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    $width = [Math]::Max(60, $Host.UI.RawUI.WindowSize.Width)
    $clean = ([string]$Text).Replace("`t", "    ")
    $pad = [Math]::Max(0, [int](($width - $clean.Length) / 2))
    Write-Host ((" " * $pad) + $clean) -ForegroundColor $Color
}

function Write-Left {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [int]$Indent = 6
    )

    $clean = ([string]$Text).Replace("`t", "    ")
    $leftPad = " " * [Math]::Max(0, $Indent)
    Write-Host ($leftPad + $clean) -ForegroundColor $Color
}

function Write-Right {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray,
        [int]$RightPadding = 2
    )

    $clean = ([string]$Text).Replace("`t", "    ")
    $width = [Math]::Max(60, $Host.UI.RawUI.WindowSize.Width)
    $pad = [Math]::Max(0, $width - $clean.Length - [Math]::Max(0, $RightPadding))
    Write-Host ((" " * $pad) + $clean) -ForegroundColor $Color
}

function Write-Bar {
    param(
        [ConsoleColor]$Color = [ConsoleColor]::Red,
        [int]$Length = 108
    )
    $len = [Math]::Max(60, $Length)
    $bar = ("/" * $len)
    Write-Left $bar -Color $Color -Indent 4
}

function Write-BrandArtLine {
    param(
        [string]$Line,
        [int]$RedChars = 30,
        [int]$Indent = 0
    )

    $safe = [string]$Line
    $pad = " " * [Math]::Max(0, $Indent)

    if ($safe.Length -le $RedChars) {
        Write-Host ($pad + $safe) -ForegroundColor DarkRed
        return
    }

    $left = $safe.Substring(0, $RedChars)
    $right = $safe.Substring($RedChars)

    Write-Host ($pad + $left) -NoNewline -ForegroundColor DarkRed
    Write-Host $right -ForegroundColor White
}

function Show-Banner {
    Clear-Host
        Write-Host ""
    Write-BrandArtLine "████  █      ███   ███  █   █ █   █  ███  ████  ████  ███ █████ ████    "
    Write-BrandArtLine "█░░░█ █░    █ ░░█ █ ░░░ █░ █ ░█░  █░█ ░░█ █░░░█ █░░░█  █░░█░░░░░█░░░█   "
    Write-BrandArtLine "████░░█░░   █████░█░ ░░░███ ░ █████░█████░████░░████░░ █░░████░░████░░  "
    Write-BrandArtLine "█░░░█ █░░   █░░░█░█░░   █░░█ ░█░░░█░█░░░█░█░░█░ █░░█░ ░█░░█░░░░ █░░█░ ░ "
    Write-BrandArtLine "████░░█████ █░░░█░░███  █░░░█ █░░░█░█░░░█░█░░░█░█░░░█░███░█████░█░░░█░  "
    Write-BrandArtLine " ░░░░ ░░░░░░ ░░  ░░ ░░░  ░░  ░ ░░  ░░░░  ░░░░  ░ ░░  ░ ░░░ ░░░░░ ░░  ░  "
    Write-BrandArtLine "  ░░░░  ░░░░░ ░   ░  ░░░  ░   ░ ░   ░ ░   ░ ░   ░ ░   ░ ░░░ ░░░░░ ░   ░ "
    Write-Host ""
        Write-Host "" -NoNewline
        Write-Host "by Jose" -ForegroundColor White
    Write-Host ""
    Write-Left "Setup Console (Windows)" -Color Gray -Indent 0
    Write-Host ""
}

function Show-Menu {
    Write-Left "[1] Setup completo (instalar todo lo faltante)" -Color White -Indent 4
    Write-Left "[2] Solo comprobacion del entorno" -Color White -Indent 4
    Write-Left "[3] Salir" -Color White -Indent 4
    Write-Host ""
}

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Add-PathIfMissing {
    param([string]$Candidate)
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
    if (-not (Test-Path $Candidate)) { return }
    $parts = ($env:PATH -split ';') | ForEach-Object { $_.Trim() }
    if ($parts -notcontains $Candidate) {
        $env:PATH = "$Candidate;$env:PATH"
    }
}

function Get-PythonCommand {
    if (Test-Command "py") { return "py" }
    if (Test-Command "python") { return "python" }
    return $null
}

function Ensure-ExecutionPolicy {
    Write-Step "Configurando politica de ejecucion para CurrentUser..."
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
    Write-Ok "Politica de ejecucion aplicada"
}

function Ensure-Scoop {
    Write-Step "Comprobando Scoop..."
    if (Test-Command "scoop") {
        Write-Ok "Scoop ya estaba instalado"
    }
    else {
        try {
            Invoke-RestMethod -Uri https://get.scoop.sh | Invoke-Expression
            Write-Ok "Scoop instalado"
        }
        catch {
            Write-Fail "No se pudo instalar Scoop"
            Write-Fail $_.Exception.Message
            throw
        }
    }
    Add-PathIfMissing "$env:USERPROFILE\scoop\shims"
}

function Install-PDToolFromZip {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$CommandName
    )

    if (Test-Command $CommandName) {
        Write-Ok "$Name ya estaba instalado"
        return
    }

    Write-Step "Instalando $Name v$Version..."
    try {
        Invoke-WebRequest -Uri $Url -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
        if (Test-Command $CommandName) {
            Write-Ok "$Name v$Version instalado"
        }
        else {
            Write-Warn "$Name instalado, pero puede requerir abrir una nueva consola para PATH"
        }
    }
    catch {
        Write-Fail "No se pudo instalar $Name desde $Url"
        Write-Fail $_.Exception.Message
        throw
    }
}

function Ensure-ProjectDiscoveryTools {
    # Orden estricto solicitado: HTTPX -> NUCLEI -> KATANA
    Write-Step "Comprobando/instalando binarios ProjectDiscovery (orden estricto)..."

    $scoopShims = "$env:USERPROFILE\scoop\shims"
    if (-not (Test-Path $scoopShims)) {
        New-Item -ItemType Directory -Path $scoopShims -Force | Out-Null
    }

    $httpxZip = "$env:USERPROFILE\httpx.zip"
    $nucleiZip = "$env:USERPROFILE\nuclei.zip"
    $katanaZip = "$env:USERPROFILE\katana.zip"

    Install-PDToolFromZip -Name "HTTPX" -Version "1.6.4" -Url "https://github.com/projectdiscovery/httpx/releases/download/v1.6.4/httpx_1.6.4_windows_amd64.zip" -ZipPath $httpxZip -DestinationPath $scoopShims -CommandName "httpx"
    Install-PDToolFromZip -Name "NUCLEI" -Version "3.3.4" -Url "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.4/nuclei_3.3.4_windows_amd64.zip" -ZipPath $nucleiZip -DestinationPath $scoopShims -CommandName "nuclei"
    Install-PDToolFromZip -Name "KATANA" -Version "1.6.1" -Url "https://github.com/projectdiscovery/katana/releases/download/v1.6.1/katana_1.6.1_windows_amd64.zip" -ZipPath $katanaZip -DestinationPath $scoopShims -CommandName "katana"

    Write-Step "Limpiando zips temporales..."
    Remove-Item "$env:USERPROFILE\httpx.zip", "$env:USERPROFILE\nuclei.zip", "$env:USERPROFILE\katana.zip" -Force -ErrorAction SilentlyContinue
    Write-Ok "Temporales eliminados"

    Write-Step "Actualizando templates de Nuclei..."
    try {
        if (Test-Command "nuclei") {
            nuclei -update-templates | Out-Host
        }
        elseif (Test-Path "$env:USERPROFILE\scoop\shims\nuclei.exe") {
            & "$env:USERPROFILE\scoop\shims\nuclei.exe" -update-templates | Out-Host
        }
        else {
            Write-Warn "Nuclei no detectado para actualizar templates"
        }
        Write-Ok "Proceso de templates completado"
    }
    catch {
        Write-Warn "No se pudo ejecutar nuclei -update-templates: $($_.Exception.Message)"
    }
}

function Ensure-Python {
    Write-Step "Comprobando Python 3.11+..."
    $pythonCmd = Get-PythonCommand
    if ($pythonCmd) {
        Write-Ok "Python ya instalado"
        return $pythonCmd
    }

    if (-not (Test-Command "winget")) {
        throw "Python no esta instalado y winget no esta disponible para instalarlo automaticamente."
    }

    Write-Step "Python no detectado. Instalando con winget..."
    winget install -e --id Python.Python.3.11 --scope user --accept-package-agreements --accept-source-agreements | Out-Host

    Add-PathIfMissing "$env:LOCALAPPDATA\Programs\Python\Python311"
    Add-PathIfMissing "$env:LOCALAPPDATA\Programs\Python\Python311\Scripts"

    $pythonCmd = Get-PythonCommand
    if (-not $pythonCmd) {
        throw "Python no esta disponible tras la instalacion automatica."
    }

    Write-Ok "Python instalado"
    return $pythonCmd
}

function Ensure-Nmap {
    Write-Step "Comprobando Nmap..."
    if (Test-Command "nmap") {
        Write-Ok "Nmap ya instalado"
        return
    }

    if (-not (Test-Command "winget")) {
        Write-Warn "Nmap no instalado y winget no disponible. Instala manualmente desde https://nmap.org/download.html#windows"
        return
    }

    try {
        Write-Step "Nmap no detectado. Instalando con winget..."
        winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements | Out-Host
        if (Test-Command "nmap") {
            Write-Ok "Nmap instalado"
        }
        else {
            Write-Warn "Nmap instalado, pero no visible aun en PATH actual"
        }
    }
    catch {
        Write-Warn "No se pudo instalar Nmap automaticamente: $($_.Exception.Message)"
    }
}

function Install-OptionalScoopTool {
    param([string]$ToolName)

    if (Test-Command $ToolName) {
        Write-Ok "$ToolName ya estaba instalado"
        return
    }

    Write-Step "Instalando $ToolName con Scoop..."
    try {
        scoop install $ToolName | Out-Host
        if (Test-Command $ToolName) {
            Write-Ok "$ToolName instalado"
        }
        else {
            Write-Warn "$ToolName instalado, pero no visible aun en PATH actual"
        }
    }
    catch {
        Write-Warn "No se pudo instalar $ToolName con Scoop: $($_.Exception.Message)"
    }
}

function Ensure-PythonProject {
    param([string]$PythonCmd)

    Write-Step "Comprobando entorno virtual .venv..."
    $venvPath = Join-Path $PSScriptRoot ".venv"
    $venvPython = Join-Path $venvPath "Scripts\python.exe"

    if (-not (Test-Path $venvPython)) {
        Write-Step "Entorno virtual no detectado. Creando .venv..."
        if ($PythonCmd -eq "py") {
            py -3 -m venv $venvPath
        }
        else {
            python -m venv $venvPath
        }
        Write-Ok "Entorno virtual creado"
    }
    else {
        Write-Ok "Entorno virtual ya existe"
    }

    if (-not (Test-Path $venvPython)) {
        throw "No se pudo inicializar .venv"
    }

    # A veces existe .venv pero incompleto (sin pip). En ese caso se recrea.
    $pipReady = $false
    try {
        & $venvPython -m pip --version | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $pipReady = $true
        }
    }
    catch {
        $pipReady = $false
    }

    if (-not $pipReady) {
        Write-Warn ".venv detectado pero incompleto (pip no disponible). Recreando entorno..."
        if (Test-Path $venvPath) {
            Remove-Item -Path $venvPath -Recurse -Force -ErrorAction SilentlyContinue
        }

        if ($PythonCmd -eq "py") {
            py -3 -m venv $venvPath
        }
        else {
            python -m venv $venvPath
        }

        if (-not (Test-Path $venvPython)) {
            throw "No se pudo recrear .venv"
        }

        & $venvPython -m ensurepip --upgrade | Out-Null
    }

    $requirementsPath = Join-Path $PSScriptRoot "requirements.txt"
    if (-not (Test-Path $requirementsPath)) {
        throw "No se encontro requirements.txt en la raiz del proyecto"
    }

    Write-Step "Instalando dependencias Python del proyecto..."
    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install --upgrade setuptools wheel
    & $venvPython -m pip install -r $requirementsPath

    # Streamlit es obligatorio para arrancar la UI, se fuerza para escenarios desde cero.
    Write-Step "Comprobando instalacion de Streamlit..."
    & $venvPython -m pip install --upgrade streamlit
    & $venvPython -m streamlit --version | Out-Host

    Write-Step "Instalando Chromium para Playwright..."
    & $venvPython -m playwright install chromium

    Write-Step "Instalando/actualizando wafw00f..."
    & $venvPython -m pip install wafw00f

    Write-Ok "Dependencias Python listas"
}

function Ensure-ProjectFolders {
    Write-Step "Comprobando carpetas de trabajo..."
    New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot "storage") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot "reports\output") -Force | Out-Null
    Write-Ok "Carpetas listas"
}

function Ensure-ExtraTools {
    Write-Step "Comprobando herramientas extra recomendadas..."
    Ensure-Nmap
    Install-OptionalScoopTool -ToolName "ffuf"
    Install-OptionalScoopTool -ToolName "feroxbuster"
    Install-OptionalScoopTool -ToolName "sqlmap"
}

function Run-EnvironmentCheck {
    Write-Step "Estado actual del entorno"
    $checks = @(
        @{ Name = "scoop"; Label = "Scoop" },
        @{ Name = "python"; Label = "Python" },
        @{ Name = "py"; Label = "Python launcher (py)" },
        @{ Name = "httpx"; Label = "HTTPX" },
        @{ Name = "nuclei"; Label = "Nuclei" },
        @{ Name = "katana"; Label = "Katana" },
        @{ Name = "nmap"; Label = "Nmap" },
        @{ Name = "ffuf"; Label = "ffuf" },
        @{ Name = "feroxbuster"; Label = "feroxbuster" },
        @{ Name = "sqlmap"; Label = "sqlmap" }
    )

    foreach ($item in $checks) {
        if (Test-Command $item.Name) {
            Write-Ok ("{0}: instalado" -f $item.Label)
        }
        else {
            Write-Warn ("{0}: no instalado" -f $item.Label)
        }
    }

    $venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        Write-Ok ".venv: disponible"

        $venvPipOk = $false
        $venvPipDetail = $null
        try {
            $venvPipOutput = & $venvPython -m pip --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $venvPipOk = $true
            }
            elseif ($venvPipOutput) {
                $venvPipDetail = (($venvPipOutput -join " ").Trim())
            }
        }
        catch {
            $venvPipDetail = $_.Exception.Message
        }

        if (-not $venvPipOk) {
            Write-Warn ".venv: incompleto (pip no disponible)"
            if ($venvPipDetail) {
                Write-Warn ("Detalle: {0}" -f $venvPipDetail)
            }
            Write-Warn "Ejecuta opcion 1 para recrear e instalar todo el entorno"
            return
        }

        # External commands do not always throw in PowerShell on non-zero exit.
        # Validate both output and exit code to avoid false positives.
        $streamlitOk = $false
        $streamlitDetail = $null

        try {
            $streamlitOutput = & $venvPython -m streamlit --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $streamlitOk = $true
            }
            elseif ($streamlitOutput) {
                $streamlitDetail = (($streamlitOutput -join " ").Trim())
            }
        }
        catch {
            $streamlitDetail = $_.Exception.Message
        }

        if ($streamlitOk) {
            Write-Ok "Streamlit (.venv): listo"
        }
        else {
            Write-Warn "Streamlit (.venv): no disponible"
            if ($streamlitDetail) {
                Write-Warn ("Detalle: {0}" -f $streamlitDetail)
            }
        }
    }
    else {
        Write-Warn ".venv: no encontrado"
    }
}

function Run-CompleteSetup {
    Ensure-ExecutionPolicy
    Ensure-Scoop
    Ensure-ProjectDiscoveryTools
    $pythonCmd = Ensure-Python
    Ensure-PythonProject -PythonCmd $pythonCmd
    Ensure-ExtraTools
    Ensure-ProjectFolders
    Run-EnvironmentCheck

    Write-Host "`n============================================================" -ForegroundColor DarkGreen
    Write-Host " Setup completado." -ForegroundColor DarkGreen
    Write-Host " Para ejecutar la herramienta:" -ForegroundColor DarkGreen
    Write-Host "   .\.venv\Scripts\Activate.ps1" -ForegroundColor DarkGreen
    Write-Host "   streamlit run app.py" -ForegroundColor DarkGreen
    Write-Host "============================================================" -ForegroundColor DarkGreen
}

Show-Banner
Show-Menu
$choice = Read-Host "Selecciona una opcion"

try {
    switch ($choice) {
        "1" {
            Run-CompleteSetup
        }
        "2" {
            Ensure-ExecutionPolicy
            Ensure-Scoop
            Run-EnvironmentCheck
        }
        "3" {
            Write-Host "Saliendo..." -ForegroundColor DarkGray
        }
        default {
            Write-Warn "Opcion no valida. Ejecuta de nuevo y elige 1, 2 o 3."
        }
    }
}
catch {
    Write-Fail "Fallo durante el setup"
    Write-Fail $_.Exception.Message
    exit 1
}


