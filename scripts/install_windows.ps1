# ==============================================================================
# BHARYDANGEROUS-Investigator — Windows PowerShell Installer Script
# Created by Ashim for the Cybersecurity Community
# ==============================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "Installing BHARYDANGEROUS-Investigator (Windows)" -ForegroundColor Cyan
Write-Host "A modular, production-grade digital forensics & incident response CLI." -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# Step 1: Detect Python 3.11+
$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
}

if (-not $PythonCmd) {
    Write-Host "[-] Error: Python is not installed or not available in PATH." -ForegroundColor Red
    Write-Host "    Please download and install Python 3.11+ from https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

$PyVersionOutput = & $PythonCmd.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$PyParts = $PyVersionOutput.Split('.')
$Major = [int]$PyParts[0]
$Minor = [int]$PyParts[1]

if ($Major -lt 3 -or ($Major -eq 3 -and $Minor -lt 11)) {
    Write-Host "[-] Error: Detected Python $PyVersionOutput. Python 3.11+ is required." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Python $PyVersionOutput detected and compatible." -ForegroundColor Green

# Step 2: Create isolated virtual environment
$VenvDir = Join-Path $PSScriptRoot "..\.venv"
if (-not (Test-Path $VenvDir)) {
    Write-Host "[*] Creating isolated virtual environment in '$VenvDir'..." -ForegroundColor Gray
    & $PythonCmd.Source -m venv $VenvDir
} else {
    Write-Host "[+] Virtual environment '$VenvDir' already exists." -ForegroundColor Green
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

# Step 3: Install dependencies
Write-Host "[*] Installing package in editable mode..." -ForegroundColor Gray
& $VenvPython -m pip install --upgrade pip setuptools wheel
& $VenvPython -m pip install -e ".[all]"

# Step 4: Run environment verification
Write-Host "[*] Running diagnostic environment verification..." -ForegroundColor Gray
$VerifyScript = Join-Path $PSScriptRoot "verify_environment.py"
& $VenvPython $VerifyScript

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "[+] BHARYDANGEROUS-Investigator installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To activate the environment in PowerShell:" -ForegroundColor Yellow
Write-Host "    .\.venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Then run:" -ForegroundColor Yellow
Write-Host "    bdinvestigator --help" -ForegroundColor White
Write-Host "    bdinvestigator doctor" -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Cyan
