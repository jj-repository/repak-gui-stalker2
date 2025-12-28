#!/bin/bash
# Repak GUI launcher

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Check for Python 3
if ! command -v python3 &>/dev/null; then
    echo "Error: Python 3 is not installed."
    exit 1
fi

# Check for tk
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "Tkinter not found."

    # Detect package manager and offer to install
    if command -v pacman &>/dev/null; then
        read -p "Install tk using pacman? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo pacman -S --noconfirm tk
        else
            echo "Tkinter is required to run this application."
            exit 1
        fi
    elif command -v apt-get &>/dev/null; then
        read -p "Install tk using apt-get? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt-get install -y python3-tk
        else
            echo "Tkinter is required to run this application."
            exit 1
        fi
    elif command -v dnf &>/dev/null; then
        read -p "Install tk using dnf? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo dnf install -y python3-tkinter
        else
            echo "Tkinter is required to run this application."
            exit 1
        fi
    else
        echo "Please install python3-tk using your distribution's package manager."
        exit 1
    fi
fi

python3 repak_gui.py
