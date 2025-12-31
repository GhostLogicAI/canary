@echo off
:: Edge Parser Launcher
:: Runs the local surface monitor

cd /d "%~dp0"
echo Starting Edge Parser...
python edge_parser.py %*
pause
