@echo off
setlocal enabledelayedexpansion

echo [1/3] Navigating to Agent Directory...
cd /d "%~dp0"

echo [2/3] Downloading Go dependencies...
"C:\Program Files\Go\bin\go.exe" get golang.org/x/sys/windows
"C:\Program Files\Go\bin\go.exe" mod tidy

echo [3/3] Compiling vap-agent.exe static binary...
if not exist "..\backend\bin" mkdir "..\backend\bin"
"C:\Program Files\Go\bin\go.exe" build -ldflags="-s -w" -o "..\backend\bin\vap-agent.exe" .\cmd\vap-agent\main.go

if %ERRORLEVEL% EQU 0 (
    echo.
    echo SUCCESS: Compiled vap-agent.exe to backend\bin\vap-agent.exe
    echo Code Signing Step (Documented for Production Pipeline):
    echo   signtool.exe sign /fd SHA256 /a /tr http://timestamp.digicert.com ..\backend\bin\vap-agent.exe
) else (
    echo.
    echo ERROR: Compilation failed with code %ERRORLEVEL%
)
