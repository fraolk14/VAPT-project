# VAP Windows Endpoint Agent - GPO / Intune / Manual Deployment Script
$ErrorActionPreference = "Stop"

param(
    [string]$BackendUrl = "http://localhost:18080",
    [string]$EnrollmentToken = ""
)

if (-not $EnrollmentToken) {
    Write-Host "Usage: .\install-agent.ps1 -BackendUrl 'http://YOUR_SERVER_IP:18080' -EnrollmentToken 'vap_tok_...'" -ForegroundColor Yellow
    exit 1
}

$InstallDir = "$env:ProgramFiles\VAP\Agent"
$ExePath = "$InstallDir\vap-agent.exe"

Write-Host "[1/4] Creating installation directory at $InstallDir..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

Write-Host "[2/4] Downloading VAP Agent binary..." -ForegroundColor Green
Invoke-WebRequest -Uri "$BackendUrl/api/agent/download" -OutFile $ExePath

Write-Host "[3/4] Enrolling endpoint with VAP platform..." -ForegroundColor Green
& "$ExePath" enroll --url "$BackendUrl" --token "$EnrollmentToken"

Write-Host "[4/4] Installing and starting VAP Windows Service..." -ForegroundColor Green
& "$ExePath" install
& "$ExePath" start

Write-Host "SUCCESS: VAP Windows Endpoint Agent deployed as automatic Windows Service." -ForegroundColor Green
