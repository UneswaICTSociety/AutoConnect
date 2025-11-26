$ErrorActionPreference = 'Stop'

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Building AutoConnect.exe with Nuitka" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Check Python is available
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Python is not installed or not in PATH"
    exit 1
}
Write-Host "[OK] Python found: $pythonVersion" -ForegroundColor Green

# Check/Install dependencies
Write-Host "`nChecking dependencies..." -ForegroundColor Yellow

$ErrorActionPreference = 'Continue'
$hasNuitka = python -c "import nuitka" 2>$null
$ErrorActionPreference = 'Stop'

if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing Nuitka..." -ForegroundColor Yellow
    pip install nuitka
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install Nuitka"
        exit 1
    }
}
else {
    Write-Host "[OK] Nuitka is installed" -ForegroundColor Green
}

# Install project dependencies if not already installed
Write-Host "`nInstalling project dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Some dependencies may not have installed correctly"
}

# Clean previous build artifacts
Write-Host "`nCleaning previous build artifacts..." -ForegroundColor Yellow
Remove-Item "AutoConnect.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "main.exe" -Force -ErrorAction SilentlyContinue
Remove-Item "main.build" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "main.dist" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[OK] Cleaned previous builds" -ForegroundColor Green

# Build with Nuitka
Write-Host "`nBuilding executable with Nuitka..." -ForegroundColor Yellow
Write-Host "This may take several minutes on first build...`n" -ForegroundColor Gray

$nuitkaArgs = @(
    "--onefile",
    "--output-filename=AutoConnect.exe",
    "--windows-disable-console",
    "--windows-company-name=UNESWA ICT Society",
    "--windows-product-name=AutoConnect",
    "--windows-file-version=1.0.0.0",
    "--windows-product-version=1.0.0.0",
    "--windows-file-description=UNESWA WiFi AutoConnect",
    "--enable-plugin=tk-inter",
    "--include-package=customtkinter",
    "--include-package-data=customtkinter",
    "--include-package=src",
    "--include-package=requests",
    "--include-package=bs4",
    "--include-package=psutil",
    "--include-package=colorlog",
    "--assume-yes-for-downloads",
    "--show-progress",
    "main.py"
)

# Add icon if it exists
if (Test-Path "assets\icon.ico") {
    $nuitkaArgs += "--windows-icon-from-ico=assets\icon.ico"
    Write-Host "[OK] Using custom icon: assets\icon.ico" -ForegroundColor Green
}

# Run Nuitka
$ErrorActionPreference = 'Continue'
python -m nuitka @nuitkaArgs
$buildExitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'

if ($buildExitCode -eq 0 -and (Test-Path "AutoConnect.exe")) {
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "[SUCCESS] BUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    $size = (Get-Item "AutoConnect.exe").Length / 1MB
    Write-Host "`nExecutable: AutoConnect.exe" -ForegroundColor Cyan
    Write-Host "Size: $([math]::Round($size, 2)) MB" -ForegroundColor Cyan
    Write-Host "`nTo run: .\AutoConnect.exe`n" -ForegroundColor Yellow
}
else {
    Write-Host "`n========================================" -ForegroundColor Red
    Write-Host "[FAILED] BUILD FAILED" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "`nNuitka build failed or AutoConnect.exe was not created." -ForegroundColor Red
    Write-Host "`nTry running with verbose output:" -ForegroundColor Yellow
    Write-Host "  python -m nuitka --onefile --show-progress --show-scons main.py`n" -ForegroundColor Gray
    exit 1
}