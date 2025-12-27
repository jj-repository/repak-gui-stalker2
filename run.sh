#!/bin/bash
# Repak GUI launcher

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check for tk
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "Tkinter not found. Installing tk..."
    sudo pacman -S --noconfirm tk
fi

python3 repak_gui.py
