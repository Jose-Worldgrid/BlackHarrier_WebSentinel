$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Script:RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:ToolsDir = Join-Path $Script:RootDir ".tools"
$Script:BinDir = Join-Path $Script:ToolsDir "bin"
$Script:TempDir = Join-Path $Script:ToolsDir "_tmp"
$Script:SqlmapDir = Join-Path $Script:ToolsDir "sqlmap"

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

    $parts = ($env:PATH -split ';') | ForEach-Object { $_.TrimEnd('\') }
    $normalized = $Candidate.TrimEnd('\')

    if ($parts -notcontains $normalized) {
        $env:PATH = "$Candidate;$env:PATH"
    }
}

function Add-UserPathIfMissing {
    param([string]$Candidate)
    if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
    if (-not (Test-Path $Candidate)) { return }

    Add-PathIfMissing $Candidate

    try {
        $current = [Environment]::GetEnvironmentVariable("Path", "User")
        if ([string]::IsNullOrWhiteSpace($current)) {
            [Environment]::SetEnvironmentVariable("Path", $Candidate, "User")
            Write-Ok "PATH de usuario actualizado: $Candidate"
            return
        }

        $parts = $current -split ';' | ForEach-Object { $_.TrimEnd('\') }
        if ($parts -notcontains $Candidate.TrimEnd('\')) {
            [Environment]::SetEnvironmentVariable("Path", "$Candidate;$current", "User")
            Write-Ok "PATH de usuario actualizado: $Candidate"
        }
    }
    catch {
        Write-Warn "No se pudo actualizar el PATH de usuario: $($_.Exception.Message)"
    }
}

function Initialize-ToolFolders {
    New-Item -ItemType Directory -Force -Path $Script:ToolsDir | Out-Null
    New-Item -ItemType Directory -Force -Path $Script:BinDir | Out-Null
    New-Item -ItemType Directory -Force -Path $Script:TempDir | Out-Null
    Add-PathIfMissing $Script:BinDir
}

function Get-PythonCommand {
    if (Test-Command "py") { return "py" }
    if (Test-Command "python") { return "python" }
    return $null
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [switch]$IgnoreExitCode
    )

    & $FilePath @Arguments
    $code = $LASTEXITCODE

    if ((-not $IgnoreExitCode) -and ($null -ne $code) -and ($code -ne 0)) {
        throw "Comando fallido ($code): $FilePath $($Arguments -join ' ')"
    }

    return $code
}

function Download-File {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$OutFile
    )

    $parent = Split-Path -Parent $OutFile
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }

    Write-Host "    Descargando: $Url" -ForegroundColor DarkGray

    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers @{ "User-Agent" = "BlackHarrier-Setup" }
    }
    catch {
        throw "No se pudo descargar $Url. Detalle: $($_.Exception.Message)"
    }
}

function Expand-ZipSafe {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (Test-Path $Destination) { Remove-Item -Recurse -Force $Destination }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force
}

function Find-ExecutableInFolder {
    param(
        [Parameter(Mandatory = $true)][string]$Folder,
        [Parameter(Mandatory = $true)][string]$ExeName
    )

    if (-not (Test-Path $Folder)) { return $null }

    $direct = Join-Path $Folder $ExeName
    if (Test-Path $direct) { return $direct }

    $found = Get-ChildItem -Path $Folder -Recurse -File -Filter $ExeName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }

    return $null
}

function Install-GitHubReleaseTool {
    param(
        [Parameter(Mandatory = $true)][string]$Owner,
        [Parameter(Mandatory = $true)][string]$Repo,
        [Parameter(Mandatory = $true)][string]$ToolCommand,
        [Parameter(Mandatory = $true)][string]$ExeName,
        [Parameter(Mandatory = $true)][string[]]$AssetPatterns
    )

    Write-Step "Comprobando $ToolCommand..."

    $targetExe = Join-Path $Script:BinDir $ExeName
    if (Test-Path $targetExe) {
        Write-Ok "$ToolCommand ya estaba instalado en .tools\bin"
        return
    }

    if (Test-Command $ToolCommand) {
        Write-Ok "$ToolCommand ya estaba instalado en el sistema"
        return
    }

    $apiUrl = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    Write-Host "    Consultando ultima release: $Owner/$Repo" -ForegroundColor DarkGray

    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "BlackHarrier-Setup" }
    }
    catch {
        throw "No se pudo consultar GitHub para $ToolCommand. Detalle: $($_.Exception.Message)"
    }

    $asset = $null
    foreach ($pattern in $AssetPatterns) {
        $asset = $release.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if ($asset) { break }
    }

    if (-not $asset) {
        $available = ($release.assets | Select-Object -ExpandProperty name) -join ", "
        throw "No se encontro asset Windows x64 para $ToolCommand. Assets disponibles: $available"
    }

    $downloadPath = Join-Path $Script:TempDir $asset.name
    $extractPath = Join-Path $Script:TempDir "$ToolCommand-extracted"

    Download-File -Url $asset.browser_download_url -OutFile $downloadPath

    if ($asset.name -match '\.zip$') {
        Expand-ZipSafe -ZipPath $downloadPath -Destination $extractPath
        $sourceExe = Find-ExecutableInFolder -Folder $extractPath -ExeName $ExeName
        if (-not $sourceExe) {
            throw "No se encontro $ExeName dentro de $($asset.name)"
        }
        Copy-Item -Path $sourceExe -Destination $targetExe -Force
    }
    elseif ($asset.name -match '\.exe$') {
        Copy-Item -Path $downloadPath -Destination $targetExe -Force
    }
    else {
        throw "Asset no soportado para ${ToolCommand}: $($asset.name)"
    }

    if (-not (Test-Path $targetExe)) {
        throw "Instalacion incompleta de $ToolCommand"
    }

    Write-Ok "$ToolCommand instalado en .tools\bin"
}

function Ensure-ExecutionPolicy {
    Write-Step "Comprobando politica de ejecucion de PowerShell..."
    try {
        $policy = Get-ExecutionPolicy
        Write-Ok "Politica efectiva actual: $policy"
        Write-Ok "El script usa -ExecutionPolicy Bypass solo durante esta ejecucion; no modifica politicas permanentes"
    }
    catch {
        Write-Warn "No se pudo consultar la politica de ejecucion: $($_.Exception.Message)"
    }
}

function Ensure-Python {
    Write-Step "Comprobando Python 3.11+..."

    $pythonCmd = Get-PythonCommand
    if ($pythonCmd) {
        try {
            if ($pythonCmd -eq "py") {
                $versionOutput = & py -3 --version 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Ok "Python detectado: $versionOutput"
                    return "py"
                }
            }
            else {
                $versionOutput = & python --version 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Ok "Python detectado: $versionOutput"
                    return "python"
                }
            }
        }
        catch { }
    }

    if (-not (Test-Command "winget")) {
        throw "Python no esta instalado y winget no esta disponible. Instala Python 3.11+ y vuelve a ejecutar el setup."
    }

    Write-Step "Python no detectado. Instalando Python con winget..."
    Invoke-External -FilePath "winget" -Arguments @("install", "-e", "--id", "Python.Python.3.12", "--accept-source-agreements", "--accept-package-agreements") -IgnoreExitCode | Out-Null

    Add-PathIfMissing "$env:LOCALAPPDATA\Programs\Python\Python312"
    Add-PathIfMissing "$env:LOCALAPPDATA\Programs\Python\Python312\Scripts"
    Add-PathIfMissing "$env:LOCALAPPDATA\Microsoft\WindowsApps"

    $pythonCmd = Get-PythonCommand
    if (-not $pythonCmd) {
        throw "Python se instalo, pero no esta visible en PATH. Cierra y abre PowerShell o revisa la instalacion."
    }

    Write-Ok "Python instalado"
    return $pythonCmd
}

function Ensure-PythonProject {
    param([Parameter(Mandatory = $true)][string]$PythonCmd)

    $venvPath = Join-Path $Script:RootDir ".venv"
    $venvPython = Join-Path $venvPath "Scripts\python.exe"

    Write-Step "Comprobando entorno virtual .venv..."

    if (-not (Test-Path $venvPython)) {
        Write-Step "Creando entorno virtual..."
        if ($PythonCmd -eq "py") {
            Invoke-External -FilePath "py" -Arguments @("-3", "-m", "venv", ".venv")
        }
        else {
            Invoke-External -FilePath $PythonCmd -Arguments @("-m", "venv", ".venv")
        }
        Write-Ok "Entorno virtual creado"
    }
    else {
        Write-Ok "Entorno virtual ya existe"
    }

    Write-Step "Actualizando pip, setuptools y wheel..."
    Invoke-External -FilePath $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel")

    $requirements = Join-Path $Script:RootDir "requirements.txt"
    if (Test-Path $requirements) {
        Write-Step "Instalando dependencias Python del proyecto..."
        Invoke-External -FilePath $venvPython -Arguments @("-m", "pip", "install", "-r", $requirements)
    }
    else {
        Write-Warn "requirements.txt no encontrado. Se instalaran dependencias minimas."
        Invoke-External -FilePath $venvPython -Arguments @("-m", "pip", "install", "streamlit", "requests", "beautifulsoup4", "playwright", "python-docx", "pandas", "dnspython", "pytest", "lxml")
    }

    Write-Step "Comprobando instalacion de Streamlit..."
    Invoke-External -FilePath $venvPython -Arguments @("-m", "streamlit", "--version")

    Write-Step "Instalando Chromium para Playwright..."
    Invoke-External -FilePath $venvPython -Arguments @("-m", "playwright", "install", "chromium")

    Write-Step "Instalando/actualizando wafw00f..."
    Invoke-External -FilePath $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "wafw00f")

    Write-Ok "Dependencias Python listas"
}

function Ensure-ProjectDiscoveryTools {
    Write-Step "Comprobando/instalando binarios ProjectDiscovery..."

    Install-GitHubReleaseTool `
        -Owner "projectdiscovery" `
        -Repo "httpx" `
        -ToolCommand "httpx" `
        -ExeName "httpx.exe" `
        -AssetPatterns @("httpx_.*windows_amd64\.zip$", "httpx_.*windows.*amd64.*\.zip$")

    Install-GitHubReleaseTool `
        -Owner "projectdiscovery" `
        -Repo "nuclei" `
        -ToolCommand "nuclei" `
        -ExeName "nuclei.exe" `
        -AssetPatterns @("nuclei_.*windows_amd64\.zip$", "nuclei_.*windows.*amd64.*\.zip$")

    Install-GitHubReleaseTool `
        -Owner "projectdiscovery" `
        -Repo "katana" `
        -ToolCommand "katana" `
        -ExeName "katana.exe" `
        -AssetPatterns @("katana_.*windows_amd64\.zip$", "katana_.*windows.*amd64.*\.zip$")

    Remove-Item -Recurse -Force $Script:TempDir -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $Script:TempDir | Out-Null
    Write-Ok "Binarios ProjectDiscovery listos"
}

function Ensure-NucleiTemplates {
    Write-Step "Actualizando templates de Nuclei..."

    $nuclei = Get-Command "nuclei" -ErrorAction SilentlyContinue
    if (-not $nuclei) {
        $localNuclei = Join-Path $Script:BinDir "nuclei.exe"
        if (Test-Path $localNuclei) { $nuclei = @{ Source = $localNuclei } }
    }

    if (-not $nuclei) {
        Write-Warn "Nuclei no disponible; no se pueden actualizar templates"
        return
    }

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $nuclei.Source
        $psi.Arguments = "-update-templates"
        $psi.WorkingDirectory = $Script:RootDir
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()

        $timeoutMs = 180000
        if (-not $proc.WaitForExit($timeoutMs)) {
            try { $proc.Kill() } catch { }
            Write-Warn "La actualizacion de templates excedio 180 segundos. Se continuara sin bloquear el setup."
            return
        }

        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()

        if ($stdout) { Write-Host $stdout }
        if ($stderr) { Write-Host $stderr -ForegroundColor DarkGray }

        if ($proc.ExitCode -eq 0) {
            Write-Ok "Templates de Nuclei actualizados"
        }
        else {
            Write-Warn "Nuclei devolvio codigo $($proc.ExitCode). El setup continuara."
        }
    }
    catch {
        Write-Warn "No se pudieron actualizar templates de Nuclei: $($_.Exception.Message)"
    }
}

function Ensure-Nmap {
    Write-Step "Comprobando Nmap..."

    $candidateDirs = @(
        "$env:ProgramFiles\Nmap",
        "${env:ProgramFiles(x86)}\Nmap"
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    foreach ($dir in $candidateDirs) {
        Add-PathIfMissing $dir
    }

    if (Test-Command "nmap") {
        Write-Ok "Nmap ya instalado"
        return
    }

    if (-not (Test-Command "winget")) {
        Write-Warn "Nmap no detectado y winget no esta disponible. Instala Nmap manualmente si necesitas escaneos avanzados."
        return
    }

    Write-Step "Nmap no detectado. Instalando con winget..."
    $code = Invoke-External -FilePath "winget" -Arguments @("install", "-e", "--id", "Insecure.Nmap", "--accept-source-agreements", "--accept-package-agreements") -IgnoreExitCode

    foreach ($dir in $candidateDirs) {
        Add-PathIfMissing $dir
    }

    if (Test-Command "nmap") {
        Write-Ok "Nmap instalado"
        return
    }

    foreach ($dir in $candidateDirs) {
        $exe = Join-Path $dir "nmap.exe"
        if (Test-Path $exe) {
            Add-PathIfMissing $dir
            Add-UserPathIfMissing $dir
            Write-Ok "Nmap instalado en $dir"
            return
        }
    }

    if ($code -eq 0) {
        Write-Warn "Winget indica que Nmap esta instalado, pero nmap.exe no es visible en esta sesion. Abre una nueva consola si la app no lo detecta."
    }
    else {
        Write-Warn "No se pudo instalar Nmap automaticamente. Codigo winget: $code"
    }
}

function Ensure-FFUF {
    Install-GitHubReleaseTool `
        -Owner "ffuf" `
        -Repo "ffuf" `
        -ToolCommand "ffuf" `
        -ExeName "ffuf.exe" `
        -AssetPatterns @("ffuf_.*windows_amd64\.zip$", "ffuf_.*windows.*amd64.*\.zip$")
}

function Ensure-Feroxbuster {
    Install-GitHubReleaseTool `
        -Owner "epi052" `
        -Repo "feroxbuster" `
        -ToolCommand "feroxbuster" `
        -ExeName "feroxbuster.exe" `
        -AssetPatterns @(".*x86_64.*windows.*\.zip$", ".*windows.*x86_64.*\.zip$", ".*windows.*amd64.*\.zip$", "feroxbuster.*windows.*\.zip$")
}

function Ensure-Sqlmap {
    Write-Step "Comprobando sqlmap..."

    $shim = Join-Path $Script:BinDir "sqlmap.cmd"
    if ((Test-Path $shim) -or (Test-Command "sqlmap")) {
        Write-Ok "sqlmap ya estaba instalado"
        return
    }

    $pythonCmd = Get-PythonCommand
    if (-not $pythonCmd) {
        Write-Warn "Python no disponible; no se puede instalar sqlmap"
        return
    }

    $zipPath = Join-Path $Script:TempDir "sqlmap-master.zip"
    $extractPath = Join-Path $Script:TempDir "sqlmap-extracted"
    Download-File -Url "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip" -OutFile $zipPath
    Expand-ZipSafe -ZipPath $zipPath -Destination $extractPath

    $sourceDir = Get-ChildItem -Path $extractPath -Directory | Where-Object { $_.Name -like "sqlmap*" } | Select-Object -First 1
    if (-not $sourceDir) {
        throw "No se encontro la carpeta de sqlmap dentro del zip descargado"
    }

    if (Test-Path $Script:SqlmapDir) { Remove-Item -Recurse -Force $Script:SqlmapDir }
    Copy-Item -Path $sourceDir.FullName -Destination $Script:SqlmapDir -Recurse -Force

    $sqlmapPy = Join-Path $Script:SqlmapDir "sqlmap.py"
    if (-not (Test-Path $sqlmapPy)) {
        throw "Instalacion incompleta de sqlmap: no existe sqlmap.py"
    }

    $cmdContent = @"
@echo off
setlocal
set SQLMAP_HOME=%~dp0..\sqlmap
python "%SQLMAP_HOME%\sqlmap.py" %*
"@
    Set-Content -Path $shim -Value $cmdContent -Encoding ASCII

    Write-Ok "sqlmap instalado en .tools\sqlmap"
}

function Ensure-ExtraTools {
    Write-Step "Comprobando herramientas extra recomendadas..."
    Ensure-Nmap
    Ensure-FFUF
    Ensure-Feroxbuster
    Ensure-Sqlmap
    Add-UserPathIfMissing $Script:BinDir
}

function Ensure-ProjectFolders {
    Write-Step "Comprobando carpetas de trabajo..."
    $folders = @(
        "reports",
        "outputs",
        "word_reports",
        "screenshots",
        "data",
        "logs",
        ".tools"
    )

    foreach ($folder in $folders) {
        New-Item -ItemType Directory -Force -Path (Join-Path $Script:RootDir $folder) | Out-Null
    }

    Write-Ok "Carpetas listas"
}

function Test-ToolAvailable {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$ExtraPaths = @()
    )

    if (Test-Command $Command) { return $true }

    foreach ($path in $ExtraPaths) {
        if (Test-Path $path) { return $true }
    }

    return $false
}

function Run-EnvironmentCheck {
    Write-Step "Estado actual del entorno"

    Add-PathIfMissing $Script:BinDir
    Add-PathIfMissing "$env:ProgramFiles\Nmap"
    Add-PathIfMissing "${env:ProgramFiles(x86)}\Nmap"

    $venvPython = Join-Path $Script:RootDir ".venv\Scripts\python.exe"
    $streamlit = Join-Path $Script:RootDir ".venv\Scripts\streamlit.exe"

    $checks = @(
        @{ Label = "Python"; Ok = [bool](Get-PythonCommand) },
        @{ Label = "Python launcher (py)"; Ok = (Test-Command "py") },
        @{ Label = "HTTPX"; Ok = (Test-ToolAvailable "httpx" @((Join-Path $Script:BinDir "httpx.exe"))) },
        @{ Label = "Nuclei"; Ok = (Test-ToolAvailable "nuclei" @((Join-Path $Script:BinDir "nuclei.exe"))) },
        @{ Label = "Katana"; Ok = (Test-ToolAvailable "katana" @((Join-Path $Script:BinDir "katana.exe"))) },
        @{ Label = "Nmap"; Ok = (Test-ToolAvailable "nmap" @("$env:ProgramFiles\Nmap\nmap.exe", "${env:ProgramFiles(x86)}\Nmap\nmap.exe")) },
        @{ Label = "ffuf"; Ok = (Test-ToolAvailable "ffuf" @((Join-Path $Script:BinDir "ffuf.exe"))) },
        @{ Label = "feroxbuster"; Ok = (Test-ToolAvailable "feroxbuster" @((Join-Path $Script:BinDir "feroxbuster.exe"))) },
        @{ Label = "sqlmap"; Ok = (Test-ToolAvailable "sqlmap" @((Join-Path $Script:BinDir "sqlmap.cmd"))) },
        @{ Label = ".venv"; Ok = (Test-Path $venvPython) },
        @{ Label = "Streamlit (.venv)"; Ok = (Test-Path $streamlit) }
    )

    foreach ($check in $checks) {
        if ($check.Ok) {
            Write-Ok "$($check.Label): instalado/listo"
        }
        else {
            Write-Warn "$($check.Label): no instalado"
        }
    }
}

function Run-CompleteSetup {
    try {
        Initialize-ToolFolders
        Ensure-ExecutionPolicy
        $pythonCmd = Ensure-Python
        Ensure-PythonProject -PythonCmd $pythonCmd
        Ensure-ProjectDiscoveryTools
        Ensure-NucleiTemplates
        Ensure-ExtraTools
        Ensure-ProjectFolders
        Run-EnvironmentCheck

        Write-Host ""
        Write-Host "============================================================" -ForegroundColor White
        Write-Host " Setup completado." -ForegroundColor White
        Write-Host " Para ejecutar la herramienta:" -ForegroundColor White
        Write-Host "   .\.venv\Scripts\Activate.ps1" -ForegroundColor White
        Write-Host "   streamlit run app.py" -ForegroundColor White
        Write-Host " Si PowerShell bloquea Activate.ps1, usa:" -ForegroundColor White
        Write-Host "   .\.venv\Scripts\activate.bat" -ForegroundColor White
        Write-Host "   streamlit run app.py" -ForegroundColor White
        Write-Host "============================================================" -ForegroundColor White
    }
    catch {
        Write-Fail "Fallo durante el setup"
        Write-Fail $_.Exception.Message
        exit 1
    }
}

Set-Location $Script:RootDir
Initialize-ToolFolders

Show-Banner
Show-Menu
$choice = Read-Host "Selecciona una opcion"

switch ($choice) {
    "1" { Run-CompleteSetup }
    "2" { Run-EnvironmentCheck }
    "3" { Write-Ok "Saliendo"; exit 0 }
    default {
        Write-Warn "Opcion no valida"
        exit 1
    }
}
