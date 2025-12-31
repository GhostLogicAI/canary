@echo off
echo ========================================
echo CANARY BUILD SCRIPT
echo ========================================
echo.

:: Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python first.
    pause
    exit /b 1
)

:: Install dependencies
echo [1/3] Installing dependencies...
pip install pyinstaller pillow psutil pyyaml --quiet

:: Build the exe
echo [2/3] Building Canary.exe...
pyinstaller --noconfirm --onefile --windowed ^
    --name "Canary" ^
    --icon "canary.ico" ^
    --add-data "config.yaml;." ^
    --add-data "canary@ghostlogic.tech.png;." ^
    --add-data "*.py;." ^
    --hidden-import PIL ^
    --hidden-import PIL.Image ^
    --hidden-import PIL.ImageTk ^
    canary_ui.py

:: Check result
if exist "dist\Canary.exe" (
    echo.
    echo [3/3] SUCCESS!
    echo.
    echo   Output: dist\Canary.exe
    echo.
    explorer dist
) else (
    echo.
    echo [ERROR] Build failed. Check output above.
)

pause
