#!/bin/bash
# Repak GUI launcher for Linux
# Supports: Arch, Debian/Ubuntu, Fedora, openSUSE, RHEL/CentOS

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Colors for output (if terminal supports it)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

echo_error() {
    echo -e "${RED}Error: $1${NC}" >&2
}

echo_warning() {
    echo -e "${YELLOW}Warning: $1${NC}"
}

echo_success() {
    echo -e "${GREEN}$1${NC}"
}

# Check for Python 3
check_python() {
    if command -v python3 &>/dev/null; then
        return 0
    elif command -v python &>/dev/null; then
        # Check if 'python' is Python 3
        if python --version 2>&1 | grep -q "Python 3"; then
            # Create alias
            PYTHON_CMD="python"
            return 0
        fi
    fi
    return 1
}

PYTHON_CMD="python3"

if ! check_python; then
    echo_error "Python 3 is not installed."
    echo "Please install Python 3 using your distribution's package manager:"
    echo "  Arch:          sudo pacman -S python"
    echo "  Debian/Ubuntu: sudo apt install python3"
    echo "  Fedora:        sudo dnf install python3"
    echo "  openSUSE:      sudo zypper install python3"
    exit 1
fi

# Check for tkinter
check_tkinter() {
    $PYTHON_CMD -c "import tkinter" 2>/dev/null
}

install_tkinter() {
    echo_warning "Tkinter not found. This is required for the GUI."
    echo ""

    # Detect package manager and offer to install
    if command -v pacman &>/dev/null; then
        read -p "Install tk using pacman? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo pacman -S --noconfirm tk
            return $?
        fi
    elif command -v apt-get &>/dev/null; then
        read -p "Install python3-tk using apt-get? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt-get install -y python3-tk
            return $?
        fi
    elif command -v dnf &>/dev/null; then
        read -p "Install python3-tkinter using dnf? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo dnf install -y python3-tkinter
            return $?
        fi
    elif command -v zypper &>/dev/null; then
        read -p "Install python3-tk using zypper? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo zypper install -y python3-tk
            return $?
        fi
    elif command -v yum &>/dev/null; then
        read -p "Install python3-tkinter using yum? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo yum install -y python3-tkinter
            return $?
        fi
    elif command -v emerge &>/dev/null; then
        echo "Gentoo detected. Please install tkinter with:"
        echo "  sudo emerge --ask dev-python/tkinter"
        return 1
    elif command -v nix-env &>/dev/null; then
        echo "Nix detected. Please ensure python3 includes tkinter."
        echo "  nix-shell -p python3"
        return 1
    else
        echo_error "Could not detect package manager."
        echo "Please install python3-tk (or equivalent) using your distribution's package manager."
        return 1
    fi

    echo_error "Tkinter is required to run this application."
    return 1
}

if ! check_tkinter; then
    if ! install_tkinter; then
        exit 1
    fi
    # Verify installation worked
    if ! check_tkinter; then
        echo_error "Tkinter installation failed. Please install manually."
        exit 1
    fi
    echo_success "Tkinter installed successfully!"
fi

# Check if repak binary exists and is executable
if [[ ! -f "$SCRIPT_DIR/repak" ]]; then
    echo_error "repak binary not found in $SCRIPT_DIR"
    echo "Please ensure the 'repak' binary is in the same directory as this script."
    exit 1
fi

if [[ ! -x "$SCRIPT_DIR/repak" ]]; then
    echo_warning "Making repak binary executable..."
    chmod +x "$SCRIPT_DIR/repak" || {
        echo_error "Failed to make repak executable. Try: chmod +x $SCRIPT_DIR/repak"
        exit 1
    }
fi

# Run the GUI
echo_success "Starting Repak GUI..."
exec $PYTHON_CMD "$SCRIPT_DIR/repak_gui.py" "$@"
