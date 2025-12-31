@echo off
:: Remove Canary from Windows Startup
:: Must be run as Administrator

cd /d "%~dp0"

echo ============================================
echo  CANARY STARTUP UNINSTALLER
echo ============================================
echo.

:: Check for admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Please right-click and "Run as administrator"
    pause
    exit /b 1
)

python canary_daemon.py uninstall
pause
