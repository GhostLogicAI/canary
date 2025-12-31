#!/bin/bash
echo "========================================"
echo "CANARY BUILD SCRIPT (macOS)"
echo "========================================"
echo ""

cd "$(dirname "$0")"

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 not found. Install Python first."
    echo "  brew install python3"
    read -p "Press Enter to exit..."
    exit 1
fi

# Install dependencies
echo "[1/3] Installing dependencies..."
pip3 install pyinstaller pillow psutil pyyaml --quiet

# Build the app
echo "[2/3] Building Canary.app..."
python3 -m PyInstaller --noconfirm --onefile --windowed \
    --name "Canary" \
    --add-data "config.yaml:." \
    --add-data "canary@ghostlogic.tech.png:." \
    --hidden-import PIL \
    --hidden-import PIL.Image \
    --hidden-import PIL.ImageTk \
    canary_ui.py

# Check result
if [ -d "dist/Canary.app" ]; then
    echo ""
    echo "[3/3] SUCCESS!"
    echo ""
    echo "  Output: dist/Canary.app"
    echo ""
    open dist/
elif [ -f "dist/Canary" ]; then
    echo ""
    echo "[3/3] SUCCESS! (Unix executable)"
    echo ""
    echo "  Output: dist/Canary"
    echo ""
    open dist/
else
    echo ""
    echo "[ERROR] Build failed. Check output above."
fi

read -p "Press Enter to exit..."
