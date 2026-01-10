# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Repak GUI** is a Python desktop application providing a graphical interface for the `repak` command-line tool (Unreal Engine .pak file utility). Designed specifically for STALKER 2 modding, it supports packing and unpacking .pak files with optional AES encryption.

**Version:** 1.4.1

## Files Structure

```
repak-gui-stalker2/
├── repak_gui.py              # Main application (single file)
├── repak_gui_config.json     # User configuration (generated)
├── repak_gui.log             # Log file (generated, rotating)
├── repak                     # Linux repak binary (expected)
├── repak.exe                 # Windows repak binary (expected)
└── CLAUDE.md                 # This file
```

## Running the Application

```bash
# Run the application
python repak_gui.py

# With drag-and-drop support (requires tkinterdnd2)
pip install tkinterdnd2
python repak_gui.py
```

## Architecture Overview

### Single-File Design

The entire application is contained in `repak_gui.py` for easy distribution alongside the repak binary.

### Core Components

1. **RepakGUI class**: Main application with all UI and logic
2. **Process Management**: Subprocess handling for repak operations
3. **Logging**: RotatingFileHandler with 5MB limit, 3 backups
4. **Drag-and-Drop**: Optional tkinterdnd2 integration

### Key Features

- Pack folders into .pak files
- Unpack .pak files to folders
- AES-256 encryption support (hex or base64 keys)
- Batch operations on multiple files
- Recent files history
- Progress indication with cancelable operations
- Path validation and security checks

## Configuration

**Config Path:** `./repak_gui_config.json` (script directory)

**Stored Settings:**
- `repak_path`: Path to repak binary
- `last_input_dir`: Last used input directory
- `last_output_dir`: Last used output directory
- `aes_key`: Saved AES key (optional)
- `recent_files`: List of recent files (max 10)
- `auto_check_updates`: Update check on startup (default: true)
- `window_geometry`: Window size/position

## Update System

**Status:** Fully implemented with SHA256 verification

**Components:**
- `_check_for_updates()`: Fetches latest release from GitHub API
- `_version_newer()`: Simple tuple-based version comparison
- `_show_update_dialog()`: Modal with Update Now / Open Releases / Later
- `_apply_update()`: Downloads, verifies SHA256 checksum, creates backup, applies update

**GitHub Integration:**
- Repository: `jj-repository/repak-gui-stalker2`
- API: `https://api.github.com/repos/jj-repository/repak-gui-stalker2/releases/latest`
- Checksum file: `repak_gui.py.sha256`

**Security Features:**
- SHA256 checksum verification required
- Creates `.py.backup` before replacing
- Aborts if checksum file missing (404)
- Deletes downloaded file if verification fails

## Dependencies

- `tkinter` (standard library)
- `tkinterdnd2` (optional, for drag-and-drop)
- `subprocess`, `threading`, `json`, `logging` (standard library)
- `re` (for AES key validation)

## Security Features

### Path Validation
```python
def _validate_path(path_str: str) -> Optional[Path]:
    # Rejects: null bytes, non-existent paths, symlink escapes
    # Returns: Canonicalized absolute path or None
```

### AES Key Validation
- Hex format: 64 characters (256-bit)
- Base64 format: 43-44 characters

### Process Management
- 1-hour timeout for long operations
- Cancelable operations
- Proper process cleanup on exit

### Thread Safety
- Atomic operation start pattern with `_try_start_operation()` / `_end_operation()`
- Lock-protected config saves
- Lock-protected current_process assignments for safe cancellation
- Update file verification hashes from disk (not memory)

## UI Constants

```python
WINDOW_WIDTH = 700
WINDOW_HEIGHT = 500
MIN_WINDOW_WIDTH = 600
MIN_WINDOW_HEIGHT = 400
LOG_FONT_SIZE = 9
```

## Testing

**Test File:** `test_repak_gui.py`

**Test Categories (85 tests):**
- `TestAESKeyValidation`: AES key format validation
- `TestRedactAESKey`: Key redaction in logs
- `TestPathValidation`: Path validation security
- `TestConfigPersistence`: Config save/load
- `TestRecentFilesLimit`: Recent files management
- `TestFindConflicts`: Conflict detection functionality
- `TestVersionDefined`: Version string validation
- `TestConstants`: Application constants
- `TestCopyConflictsToFolders`: Conflict resolution

**Running Tests:**
```bash
python -m pytest test_repak_gui.py -v
```

## Logging

**Log File:** `./repak_gui.log`

**Configuration:**
- RotatingFileHandler
- Max 5MB per file
- 3 backup files retained
- Format: `%(asctime)s - %(levelname)s - %(message)s`

## Known Issues / Technical Debt

1. **Config in script directory**: Should use `~/.config/repak-gui/`
2. **Drag-and-drop not implemented**: tkinterdnd2 is imported but feature not wired up

## Recent Fixes (January 2026)

- Fixed root.after() call that was passing dict as argument (progress label now updates correctly during batch operations)
- Added lock protection around self.current_process assignments to prevent race conditions during cancellation
- Added validation for empty pak name after sanitization to prevent creating invalid `.pak` files
- Fixed zombie process leak on Unix (added wait() after terminate() with kill() fallback)

## Common Development Tasks

### Adding auto_check_updates UI toggle
1. Add checkbox to settings area
2. Connect to config save/load
3. Check setting before startup update check

### Modifying repak command execution
- `_run_repak_pack()`: Pack operation
- `_run_repak_unpack()`: Unpack operation
- `_execute_repak()`: Core subprocess execution

## Platform Notes

### Windows
- Expects `repak.exe` in script directory or PATH
- Uses native file dialogs

### Linux
- Expects `repak` binary in script directory or PATH
- Drag-and-drop may not work on Wayland without additional setup

---

## Review Status

> **Last Full Review:** 2026-01-10
> **Status:** ✅ Production Ready

### Security Review ✅
- [x] Path validation (null bytes, symlink escapes)
- [x] AES key validation (hex/base64 format)
- [x] AES key redaction in logs
- [x] No command injection (proper subprocess argument passing)
- [x] SHA256 verification for updates
- [x] Backup before update
- [x] Download verification from disk (not memory)

### Thread Safety Review ✅
- [x] Atomic operation start/end pattern
- [x] Lock-protected config saves
- [x] Lock-protected process assignments
- [x] Safe cancellation handling

### Code Quality ✅
- [x] All tests passing (85 tests)
- [x] Logging with rotation
- [x] Progress indication
- [x] Cancelable operations

## Quality Standards

**Target:** STALKER 2 modding tool - reliable, easy to use alongside repak binary

| Aspect | Standard | Status |
|--------|----------|--------|
| Test Coverage | Path validation, AES validation tested | ✅ Met |
| Security | No path escapes, safe key handling | ✅ Met |
| Thread Safety | No race conditions in pack/unpack | ✅ Met |
| UX | Clear progress, cancelable, logs visible | ✅ Met |
| Documentation | CLAUDE.md current | ✅ Met |

## Intentional Design Decisions

| Decision | Rationale |
|----------|-----------|
| Single-file design | Easy distribution - just drop alongside repak binary |
| Config in script directory | Portable with the tool; users expect it next to the exe |
| 1-hour operation timeout | Large pak files take time; better too long than false timeout |
| Optional tkinterdnd2 | Graceful degradation if not installed |
| Recent files (max 10) | Enough for convenience without bloat |

## Won't Fix (Accepted Limitations)

| Issue | Reason |
|-------|--------|
| Config in script directory | Intentional for portability; users expect tool to be self-contained |
| Drag-and-drop not wired up | tkinterdnd2 imported but DnD code incomplete; low priority |
| No multi-file progress bars | Single progress label sufficient; batch shows count |

## Completed Optimizations

- ✅ root.after() fix for progress updates
- ✅ Lock protection for process cancellation
- ✅ Empty pak name validation
- ✅ Thread-safe operation management
- ✅ Rotating log files

**DO NOT further optimize:** Pack/unpack speed is determined by repak binary and disk I/O. GUI is just a wrapper.
