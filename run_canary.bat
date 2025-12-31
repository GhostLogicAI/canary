@echo off
:: Canary UI Launcher
:: Runs the desktop alert mascot

cd /d "%~dp0"
echo Starting Canary UI...
pythonw canary_ui.py %*
