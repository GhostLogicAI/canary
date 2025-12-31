#!/bin/bash
echo "========================================"
echo "CANARY BUILD SCRIPT (Linux)"
echo "========================================"
echo ""

cd "$(dirname "$0")"

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python3 not found."
    echo "  sudo apt install python3 python3-pip python3-tk"
    exit 1
fi

# Install dependencies
echo "[1/3] Installing dependencies..."
pip3 install pyinstaller pillow psutil pyyaml --quiet --user

# Build
echo "[2/3] Building Canary..."
python3 -m PyInstaller --noconfirm --onefile \
    --name "Canary" \
    --add-data "config.yaml:." \
    --add-data "canary@ghostlogic.tech.png:." \
    --hidden-import PIL \
    --hidden-import PIL.Image \
    --hidden-import PIL.ImageTk \
    canary_ui.py

if [ -f "dist/Canary" ]; then
    echo ""
    echo "[3/3] SUCCESS!"
    echo "  Output: dist/Canary"
    chmod +x dist/Canary
else
    echo "[ERROR] Build failed."
fi
