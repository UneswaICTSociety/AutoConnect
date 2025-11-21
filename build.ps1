$ErrorActionPreference = 'Continue'

Write-Host "Building AutoConnect.exe..."

$hasNuitka = python -c "import nuitka" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing Nuitka..."
    pip install nuitka
}

Write-Host "Trying Nuitka..."
$nuitkaArgs = @(
    "--onefile",
    "--windows-disable-console",
    "--output-filename=AutoConnect.exe",
    "--remove-output",
    "main.py"
)

if (Test-Path "assets\icon.ico") {
    $nuitkaArgs += "--windows-icon-from-ico=assets\icon.ico"
}

python -m nuitka @nuitkaArgs 2>$null

if (Test-Path "main.exe") {
    Move-Item "main.exe" "AutoConnect.exe" -Force
    $size = (Get-Item "AutoConnect.exe").Length / 1MB
    Write-Host "Done! AutoConnect.exe created with Nuitka ($([math]::Round($size, 1)) MB)"
    Write-Host "Run: .\AutoConnect.exe"
} else {
    Write-Host "Nuitka failed, trying PyInstaller..."
    
    $hasPyInstaller = python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) {
        pip install pyinstaller
    }
    
    $pyArgs = @(
        "--onefile",
        "--name=AutoConnect",
        "--noconsole",
        "--clean",
        "main.py"
    )
    
    if (Test-Path "assets\icon.ico") {
        $pyArgs += "--icon=assets\icon.ico"
    }
    
    python -m PyInstaller @pyArgs
    
    if (Test-Path "dist\AutoConnect.exe") {
        Move-Item "dist\AutoConnect.exe" "." -Force
        Remove-Item "dist" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "build" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "AutoConnect.spec" -Force -ErrorAction SilentlyContinue
        
        $size = (Get-Item "AutoConnect.exe").Length / 1MB
        Write-Host "Done! AutoConnect.exe created with PyInstaller ($([math]::Round($size, 1)) MB)"
        Write-Host "Run: .\AutoConnect.exe"
    } else {
        Write-Error "Both Nuitka and PyInstaller failed"
    }
}