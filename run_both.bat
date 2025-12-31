@echo off
:: Run both parser and canary together
:: Parser in background, Canary visible

cd /d "%~dp0"
echo Starting Canary System...

:: Start parser in background
start /min cmd /c "python edge_parser.py"

:: Wait a moment for parser to initialize
timeout /t 2 /nobreak >nul

:: Start canary UI
pythonw canary_ui.py

echo Canary system running.
