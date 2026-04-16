# Repak GUI for STALKER 2

[![Build](https://github.com/jj-repository/repak-gui-stalker2/actions/workflows/build-release.yml/badge.svg)](https://github.com/jj-repository/repak-gui-stalker2/actions/workflows/build-release.yml)
[![Tests](https://github.com/jj-repository/repak-gui-stalker2/actions/workflows/test.yml/badge.svg)](https://github.com/jj-repository/repak-gui-stalker2/actions/workflows/test.yml)
[![Latest Release](https://img.shields.io/github/v/release/jj-repository/repak-gui-stalker2)](https://github.com/jj-repository/repak-gui-stalker2/releases/latest)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

A graphical wrapper for [repak](https://github.com/trumank/repak) — the Unreal Engine .pak file tool. Built specifically for STALKER 2 modding.

## Before You Start

You need two things before using this tool:

### 1. The repak binary

The `repak` binary handles all pak/unpack operations. This GUI is just a wrapper around it.

- **Pre-built releases** already include `repak` — download from [Releases](https://github.com/jj-repository/repak-gui-stalker2/releases/latest)
- **From source**: download `repak` from [trumank/repak](https://github.com/trumank/repak/releases) and place it in the same directory as `repak_gui.py`

### 2. The STALKER 2 AES encryption key (for unpacking game paks)

STALKER 2 game paks are AES-256 encrypted. You need the decryption key to unpack them.

**Where to find the key:**
- Search the [STALKER 2 Modding Wiki](https://s2modding.wiki/) or modding Discord servers for the current AES key
- The key is a 64-character hex string (e.g., `0x1A2B3C...`)
- Paste it into the "AES-256 Key" field in the GUI

**You do NOT need an AES key for:**
- Unpacking mods made by other modders (most are unencrypted)
- Packing your own mods

### 3. Windows only: Oodle DLL

Windows users must place `oo2core_9_win64.dll` in the same directory as the executable.

**Where to find it:**
1. Go to your STALKER 2 install folder: `Stalker2/Content/Paks/`
2. Copy `oo2core_9_win64.dll` next to `RepakGUI.exe`

This is a proprietary Oodle compression library from Epic Games and cannot be bundled due to licensing.

## Installation

### Option A: Pre-built executable (recommended)

Download from [Releases](https://github.com/jj-repository/repak-gui-stalker2/releases/latest):

| Platform | File | Notes |
|----------|------|-------|
| Windows | `RepakGUI.exe` | Needs `oo2core_9_win64.dll` alongside |
| Linux | `RepakGUI-Linux` | `chmod +x RepakGUI-Linux` then run |

### Option B: Run from source (Linux)

```bash
chmod +x run.sh
./run.sh
```

The launcher auto-detects your package manager and installs tkinter if missing.

### Option C: Run with Python directly

```bash
python3 repak_gui.py
```

Requires Python 3.7+ and tkinter (usually bundled with Python).

## How to Use

### Setting the output folder

By default, output goes to your **Downloads** folder. To change it:

1. Click **Set Output Folder** (below the tabs)
2. Pick any folder — unpacked files go to `<folder>/unpackedfiles/`, packed files to `<folder>/packedfiles/`
3. Click **Reset** to go back to Downloads

The setting is saved between sessions.

### Unpacking a game pak (extracting files)

1. Open the **Unpack** tab
2. Click **Browse** (or `Ctrl+O`) and select a `.pak` file
3. If it's an encrypted game pak, paste the AES key in the **AES-256 Key** field at the bottom
4. Click **Unpack**
5. Files go to `<output folder>/unpackedfiles/<pakname>/`

### Packing a mod (creating a .pak)

1. Open the **Pack** tab
2. Click **Browse** and select your mod folder (must follow the game's directory structure)
3. Enter a pak name — use STALKER 2 naming convention: `~mods_yourmodname_P`
4. Click **Pack**
5. Output goes to `<output folder>/packedfiles/`

### Batch unpacking multiple paks

1. Open the **Batch Unpack** tab
2. **Add Files** or **Add Folder** to queue `.pak` files
3. Right-click the list to reorder (Move Up/Down) or remove entries
4. Click **Unpack All**
5. Press `Escape` to cancel at any time

### Viewing pak contents without unpacking

1. Open the **Info/List** tab
2. Browse for a `.pak` file
3. **Show Info** for metadata, **List Contents** for file listing

## STALKER 2 Modding Tips

### Pak naming convention

Use the `~mods` prefix for mod paks:
- Format: `~mods_modname_P.pak`
- Example: `~mods_betterweapons_P.pak`

This ensures mods load with correct priority.

### Recommended workflow

1. Unpack the game pak containing the files you want to modify
2. Find and edit the relevant files
3. Recreate the game's directory structure in a new folder with only your changed files
4. Pack with `~mods_yourmod_P` name
5. Place the `.pak` in `Stalker2/Content/Paks/~mods/`
6. Use `find_conflicts.py` to check compatibility with other mods

### Detecting mod conflicts

```bash
python3 find_conflicts.py
```

Scans `unpackedfiles/` for `.cfg` files that appear in multiple mods with different content. Copies conflicting versions into `conflicts/` for side-by-side comparison.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Browse for pak file |
| `Ctrl+L` | Clear log |
| `Ctrl+E` | Export log to file |
| `Ctrl+Q` | Quit |
| `Escape` | Cancel current operation |

## Updates

- **Manual check**: Help menu > Check for Updates
- **Auto-check on startup**: Disabled by default. Enable via Help menu > "Check for Updates on Startup"
- Updates are verified with SHA-256 checksums and a backup is created before applying

## Output directories

Default output folder: `~/Downloads` (configurable via **Set Output Folder** button).

| Directory | Contents |
|-----------|----------|
| `<output folder>/unpackedfiles/` | Extracted pak contents |
| `<output folder>/packedfiles/` | Created `.pak` files |
| `conflicts/` | Conflict analysis output (in script dir) |
| `repak_gui.log` | Operation log (rotated, 5MB max, in script dir) |
| `repak_gui_config.json` | Saved settings (in script dir) |

## Troubleshooting

### Linux: "tkinter not found"

Install via your package manager:
- **Arch**: `sudo pacman -S tk`
- **Debian/Ubuntu**: `sudo apt install python3-tk`
- **Fedora**: `sudo dnf install python3-tkinter`
- **openSUSE**: `sudo zypper install python3-tk`

Or use `./run.sh` which handles this automatically.

### Windows: operation fails immediately

Make sure `oo2core_9_win64.dll` is in the same directory as the executable. See [Before You Start](#3-windows-only-oodle-dll).

### "repak binary not found"

Place the `repak` binary (Linux) or `repak.exe` (Windows) in the same directory as the GUI.

### Encrypted pak won't unpack

- Verify the AES key is correct (64 hex characters or base64)
- Make sure there are no leading/trailing spaces
- The key must match the game version — keys can change with game updates

## Development

```bash
# Run tests
pip install pytest pytest-cov
pytest test_repak_gui.py -v

# With coverage
pytest test_repak_gui.py -v --cov=repak_gui --cov=find_conflicts

# Lint
pip install ruff
ruff check repak_gui.py find_conflicts.py
```

## Credits

Built on top of [repak](https://github.com/trumank/repak) by trumank. All pak/unpack functionality comes from repak — this project provides the graphical interface.

## License

[MIT](LICENSE)
