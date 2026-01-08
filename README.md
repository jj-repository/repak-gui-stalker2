# Repak GUI for STALKER 2

[![Build](https://github.com/jj-repository/repak-gui-stalker2/actions/workflows/build-release.yml/badge.svg)](https://github.com/jj-repository/repak-gui-stalker2/actions/workflows/build-release.yml)
[![Latest Release](https://img.shields.io/github/v/release/jj-repository/repak-gui-stalker2)](https://github.com/jj-repository/repak-gui-stalker2/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/jj-repository/repak-gui-stalker2/total)](https://github.com/jj-repository/repak-gui-stalker2/releases)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## ✨ Features

### Core Functionality
- **Unpack/Pack PAK Files** - Extract and create .pak files with ease
- **Batch Operations** - Process multiple .pak files at once
- **AES-256 Encryption Support** - Handle encrypted pak files
- **Info & List** - View pak file metadata and contents

### User Experience
- **Recent Files** - Quick access to previously opened files (up to 10)
- **Keyboard Shortcuts** - Efficient workflow with hotkeys
- **Context Menus** - Right-click options in batch list
- **Progress Tracking** - Visual feedback during operations
- **Operation Cancellation** - Cancel long-running operations with Escape key
- **Configuration Persistence** - Remembers window size and recent files

### Advanced Features
- **File-based Logging** - All operations logged to `repak_gui.log`
- **Export Logs** - Save operation logs to text files
- **Path Validation** - Security against path traversal attacks
- **AES Key Redaction** - Encryption keys hidden in logs for security
- **Type Hints** - Full type annotations for better code quality

### Security Features
- ✅ Path traversal protection
- ✅ AES key redaction in logs
- ✅ Binary integrity validation
- ✅ SHA-256 file hashing (in conflict detection)
- ✅ Input validation and sanitization

## 📋 Requirements

- Python 3.7 or higher
- tkinter (usually included with Python)
- repak binary (included in this repository)

### Optional
- `tkinterdnd2` - For drag-and-drop support (not required)
- `pytest` - For running tests

## 🚀 Installation

### Method 1: Direct Run (Linux)
```bash
# Make the launcher executable
chmod +x run.sh

# Run the application
./run.sh
```

### Method 2: Python
```bash
# Install optional dependencies (if desired)
pip install -r requirements.txt

# Run directly
python3 repak_gui.py
```

### Method 3: Standalone Executables
Download pre-built binaries from the [Releases](https://github.com/yourusername/repak_gui_forstalker2/releases) page:
- **Windows**: `repak-gui.exe`
- **Linux**: `repak-gui`

## 📖 Usage

### Unpack Tab
1. Click "Browse..." or press **Ctrl+O** to select a .pak file
2. Enter AES key if the pak is encrypted
3. Click "Unpack" to extract to `unpackedfiles/`

### Pack Tab
1. Select source directory containing your mod files
2. Enter a name for the .pak file (e.g., `~mods_mymod_P`)
3. Click "Pack" to create pak in `packedfiles/`

### Batch Unpack Tab
1. Add files via "Add Files..." or "Add Folder..."
2. Reorder with right-click context menu (Move Up/Down)
3. Click "Unpack All" to process all files
4. Press **Escape** to cancel at any time

### Info/List Tab
- **Show Info**: Display pak file metadata
- **List Contents**: View all files in the pak

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Open/Browse PAK file |
| `Ctrl+L` | Clear log |
| `Ctrl+E` | Export log to file |
| `Ctrl+Q` | Quit application |
| `Escape` | Cancel current operation |

## 🖱️ Context Menu (Batch List)

Right-click on the batch list for:
- Remove Selected
- Clear All
- Move Up/Down - Reorder files

## 📁 Output Directories

- **Unpacked files**: `unpackedfiles/`
- **Packed files**: `packedfiles/`
- **Conflict analysis**: `conflicts/` (when using find_conflicts.py)
- **Logs**: `repak_gui.log`
- **Configuration**: `repak_gui_config.json`

## 🔧 Utilities

### Find Conflicts (find_conflicts.py)
Detects conflicting .cfg files across multiple unpacked mods:

```bash
python3 find_conflicts.py
```

This tool:
- Scans all unpacked mods in `unpackedfiles/`
- Identifies duplicate filenames with different content (SHA-256 hashing)
- Organizes conflicts into `conflicts/` folder for easy comparison

## 🧪 Testing

Run the test suite:

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest test_repak_gui.py -v

# Run with coverage
pytest test_repak_gui.py -v --cov=repak_gui --cov=find_conflicts
```

## 🔨 Building

Create standalone executables:

```bash
# Install PyInstaller
pip install pyinstaller

# Linux
pyinstaller --onefile --name repak-gui repak_gui.py

# Windows (with GUI mode)
pyinstaller --onefile --windowed --name repak-gui repak_gui.py
```

## 🐛 Troubleshooting

### Linux: Tkinter not found
The launcher will auto-detect your package manager and offer to install:
- **Arch**: `sudo pacman -S tk`
- **Debian/Ubuntu**: `sudo apt-get install python3-tk`
- **Fedora**: `sudo dnf install python3-tkinter`

### Windows: Missing DLL
Ensure `oo2core_9_win64.dll` is in the same directory as the executable.

### Operation Fails
1. Check the log output in the application
2. View detailed logs in `repak_gui.log`
3. Export logs with **Ctrl+E** for sharing

## 🎮 STALKER 2 Modding Tips

### Pak Naming Convention
Use the `~mods` prefix for mod paks:
- Format: `~mods_modname_P.pak`
- Example: `~mods_betterweapons_P.pak`

This ensures mods load with correct priority in STALKER 2.

### Recommended Workflow
1. Unpack existing game paks to study structure
2. Create your mod folder following the game's directory structure
3. Pack with appropriate name
4. Test in-game
5. Use find_conflicts.py to detect compatibility issues with other mods

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

## 🙏 Credits

This GUI wrapper is built on top of **[repak](https://github.com/trumank/repak)** by trumank.

repak is a powerful command-line tool for working with Unreal Engine .pak files. All pak/unpak functionality is provided by repak - this project simply provides a graphical interface for convenience.

## 📄 License

This GUI wrapper is provided as-is for the STALKER 2 modding community. Please refer to the [original repak repository](https://github.com/trumank/repak) for its license terms.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

### Development Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/repak_gui_forstalker2.git
cd repak_gui_forstalker2

# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest test_repak_gui.py -v
```

## 🌟 Features Comparison

| Feature | v1.0.0 | v1.1.0 | v1.2.0 | v1.3.0 |
|---------|---------|---------|---------|---------|
| Basic unpack/pack | ✅ | ✅ | ✅ | ✅ |
| Batch operations | ✅ | ✅ | ✅ | ✅ |
| AES encryption | ✅ | ✅ | ✅ | ✅ |
| Recent files | ❌ | ✅ | ✅ | ✅ |
| Keyboard shortcuts | ❌ | ✅ | ✅ | ✅ |
| Operation cancellation | ❌ | ✅ | ✅ | ✅ |
| File-based logging | ❌ | ✅ | ✅ | ✅ |
| Export logs | ❌ | ✅ | ✅ | ✅ |
| Context menus | ❌ | ✅ | ✅ | ✅ |
| Configuration persistence | ❌ | ✅ | ✅ | ✅ |
| Security hardening | ⚠️ Basic | ✅ Advanced | ✅ Advanced | ✅ Advanced |
| Type hints | ❌ | ✅ | ✅ | ✅ |
| Unit tests | ❌ | ✅ | ✅ (31 tests) | ✅ (31 tests) |
| AES key validation | ❌ | ❌ | ✅ | ✅ |
| Windows full compatibility | ⚠️ Partial | ⚠️ Partial | ✅ Full | ✅ Full |
| Thread safety locks | ❌ | ❌ | ✅ | ✅ |
| Subprocess timeout protection | ❌ | ❌ | ✅ | ✅ |

## 📞 Support

For issues specific to:
- **This GUI**: Open an issue on this repository
- **Repak functionality**: Refer to the [repak repository](https://github.com/trumank/repak)
- **STALKER 2 modding**: Visit STALKER 2 modding communities

---

**Made with ❤️ for the STALKER 2 modding community**
