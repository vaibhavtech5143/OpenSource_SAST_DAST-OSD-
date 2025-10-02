# Security Scanner Launcher Script (Windows PowerShell)

Write-Host "Starting SAST/DAST Security Scanner..." -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green

# Check if Docker is installed
try {
    $dockerVersion = docker --version 2>$null
    if (-not $dockerVersion) {
        throw "Docker not found"
    }
    Write-Host "Docker found: $dockerVersion" -ForegroundColor Yellow
} catch {
    Write-Host "Error: Docker is not installed. Please install Docker and try again." -ForegroundColor Red
    exit 1
}

# Check if Python is installed
try {
    $pythonVersion = python --version 2>$null
    if (-not $pythonVersion) {
        throw "Python not found"
    }
    Write-Host "Python found: $pythonVersion" -ForegroundColor Yellow
} catch {
    Write-Host "Error: Python is not installed. Please install Python and try again." -ForegroundColor Red
    exit 1
}

# Install Python dependencies if requirements.txt exists
if (Test-Path "requirements.txt") {
    Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
    python -m pip install -r requirements.txt
}

# Run the security scanner
Write-Host "Launching security scanner..." -ForegroundColor Green
python scanner.py

Write-Host "Security scan completed. Check the output directory for results." -ForegroundColor Green