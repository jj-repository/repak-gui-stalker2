# Changelog

All notable changes to Repak GUI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] - 2026-01-02

### Fixed
- **Thread Safety** - Fixed race condition in `cancel_operation()` by adding lock protection
- **Log Export Encoding** - Added explicit UTF-8 encoding to log export to prevent encoding issues on non-ASCII content

---

## [1.2.0] - 2026-01-01

### Added
- **AES Key Validation** - Validates AES key format (64-char hex or base64) with user warnings for invalid formats
- **Batch Cancellation** - Batch unpack now supports cancellation with Escape key or Cancel button
- **Subprocess Timeout** - 1-hour timeout prevents operations from hanging indefinitely
- **Windows Compatibility** - Full Windows support with:
  - Automatic `repak.exe` detection
  - `CREATE_NO_WINDOW` flag to hide console windows
  - Platform-specific path handling
- **Extended Linux Distro Support** - `run.sh` now supports:
  - openSUSE (zypper)
  - RHEL/CentOS (yum)
  - Gentoo (emerge) with manual instructions
  - Nix with guidance
- **Colored Terminal Output** - `run.sh` displays colored messages (red errors, yellow warnings, green success)
- **Thread Safety Lock** - Added `threading.Lock()` for protecting shared state access

### Security
- **Removed AES Key Storage** - AES keys are no longer stored in config file (were previously saved in plaintext)
- **Legacy Key Cleanup** - Automatically removes `last_aes_key` from existing config files on load

### Improved
- **Subprocess Handling** - Complete rewrite with:
  - Explicit `stdout.close()` to prevent resource leaks
  - Null checks before reading stdout
  - Proper cleanup in `finally` blocks
  - Graceful termination with 5-second timeout before force kill
- **Error Handling** - Replaced broad `except Exception` with specific types:
  - `FileNotFoundError` for missing binaries
  - `PermissionError` for access issues
  - `OSError` for system errors
  - `json.JSONDecodeError` for config parsing
  - `subprocess.TimeoutExpired` for hung processes
- **Thread-Safe Operations** -
  - `_add_to_recent_files()` now uses lock and schedules UI updates on main thread
  - `_save_config()` copies data under lock before writing
- **Logging Path** - Log file now always written to script directory, not current working directory
- **UTF-8 Encoding** - Explicit encoding on all file read/write operations
- **find_conflicts.py Improvements** -
  - Added comprehensive type hints
  - Fixed potential `IndexError` on empty relative paths
  - Added proper exit codes from `main()`
  - Improved mod name sanitization (handles `:` character)
  - Better error reporting with `sys.stderr`

### Fixed
- Fixed potential crash when `relative.parts` is empty in `find_conflicts.py`
- Fixed log file being created in wrong directory when run from different working directory
- Fixed batch unpack not supporting cancellation
- Fixed process cleanup leaving zombie processes on cancellation
- Fixed unit tests with proper method binding for instance methods

### Developer
- **31 Unit Tests** - All tests passing with proper mocking
- **New Test Categories** - Added tests for:
  - AES key validation
  - Constants verification
  - Subprocess timeout
  - Platform detection
  - Conflict copying and sanitization
- **Code Constants** - Added:
  - `SUBPROCESS_TIMEOUT` (3600 seconds)
  - `PROCESS_POLL_INTERVAL` (0.1 seconds)
  - `IS_WINDOWS` (platform detection)
  - `AES_KEY_HEX_PATTERN` and `AES_KEY_BASE64_PATTERN` (regex patterns)

---

## [1.1.0] - 2025-01-XX

### Added
- **Operation Cancellation** - Cancel long-running operations with Escape key or Cancel button
- **Recent Files Menu** - Quick access to up to 10 recently opened .pak files
- **Keyboard Shortcuts** - Full keyboard shortcut support:
  - `Ctrl+O` - Browse for PAK file
  - `Ctrl+L` - Clear log
  - `Ctrl+E` - Export log
  - `Ctrl+Q` - Quit application
  - `Escape` - Cancel operation
- **Context Menu (Batch List)** - Right-click menu with:
  - Remove Selected
  - Clear All
  - Move Up/Down - Reorder files in batch queue
- **File-based Logging** - All operations logged to `repak_gui.log`
- **Export Logs** - Export log contents to timestamped text files
- **Configuration Persistence** - Saves window geometry and recent files to `repak_gui_config.json`
- **Menu Bar** - File and Help menus with:
  - Recent Files submenu
  - Export Log option
  - Keyboard Shortcuts help
  - About dialog
- **Progress Tracking** - Cancel button shown during operations
- **Batch Progress Updates** - Progress label updates with current file being processed
- **Type Hints** - Full type annotations throughout codebase
- **Unit Tests** - Comprehensive test suite with pytest
- **Requirements File** - `requirements.txt` for dependencies

### Security
- **AES Key Redaction** - Encryption keys now redacted in all log output as `[REDACTED]`
- **Path Validation** - Comprehensive path validation to prevent path traversal attacks
- **Binary Integrity Checks** - Validates repak binary existence and executable permissions
- **SHA-256 Hashing** - Replaced MD5 with SHA-256 in `find_conflicts.py`
- **Directory Deletion Validation** - Safety checks before `shutil.rmtree()` operations
- **Input Sanitization** - All user inputs validated and sanitized
- **Chunked File Reading** - Memory-efficient file hashing (8KB chunks)

### Improved
- **Error Handling** - Comprehensive try-except blocks around all file operations
- **Shell Script** - Enhanced `run.sh` with:
  - Multi-distro support (Arch, Debian/Ubuntu, Fedora)
  - User confirmation before package installation
  - Python 3 existence checks
  - Quoted variables for paths with spaces
  - Proper exit codes
- **Code Quality** - Eliminated magic numbers with named constants:
  - `WINDOW_WIDTH`, `WINDOW_HEIGHT`
  - `MIN_WINDOW_WIDTH`, `MIN_WINDOW_HEIGHT`
  - `PROGRESS_BAR_INTERVAL`
  - `LOG_FONT_SIZE`
  - `HASH_CHUNK_SIZE`
  - `MAX_RECENT_FILES`
- **Window Title** - Now displays version number
- **Progress Labels** - Updated during batch operations to show current file
- **Log Messages** - Improved with Unicode symbols (✓, ✗, ⚠️)
- **Thread Safety** - Proper use of `root.after()` for UI updates from threads

### Fixed
- Bare except clause changed to `except Exception:`
- Progress bar now properly hides after batch operations complete
- File paths with spaces now properly handled in shell script
- Batch validation now occurs before starting operations
- Configuration properly saved on window close

### Developer
- Added comprehensive docstrings to all methods
- Type hints for better IDE support and code clarity
- Unit tests with pytest and coverage reporting
- Build instructions for PyInstaller executables
- Development setup documentation in README

## [1.0.0] - 2025-01-XX

### Added
- Initial release
- Basic GUI wrapper for repak
- Unpack .pak files
- Pack directories into .pak files
- Batch unpack multiple files
- AES-256 encryption support
- Info and List commands
- Progress bar with indeterminate mode
- Scrolled text log output
- Fixed output directories (`unpackedfiles/`, `packedfiles/`)
- `find_conflicts.py` utility for detecting mod conflicts
- GitHub Actions for automated builds (Linux and Windows)
- Shell launcher script (`run.sh`) for Linux

### Features
- Tabbed interface (Unpack, Pack, Info/List, Batch Unpack)
- Auto-create output directories
- Subfolder creation based on pak filename
- Batch file count tracking
- Drag-and-drop-ready architecture (optional)
- Monospace font for better log readability

---

## Legend

- **Added** - New features
- **Changed** - Changes in existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Security improvements
- **Improved** - Enhancements to existing features
- **Developer** - Changes for developers

---

## Upgrade Guide

### From 1.1.0 to 1.2.0

No breaking changes! Simply replace the files and run. Notable changes:

1. **Security Improvement** - If you had an AES key saved in your config, it will be automatically removed on first launch (keys should not be stored in plaintext)
2. **Windows Users** - The application now properly detects `repak.exe` automatically
3. **Batch Operations** - You can now cancel batch unpacking mid-operation
4. **Stability** - Long-running operations will timeout after 1 hour instead of hanging forever

### From 1.0.0 to 1.1.0

No breaking changes! Simply replace the files and run. Your workflow remains unchanged, but you gain:

1. **Configuration File** - A new `repak_gui_config.json` will be created automatically
2. **Log File** - Operations will be logged to `repak_gui.log`
3. **Menu Bar** - New File and Help menus at the top
4. **Keyboard Shortcuts** - Start using hotkeys for faster workflow
5. **Recent Files** - Previously opened files appear in File > Recent Files

All existing features work exactly as before, just with more options and better security!

---

## Future Roadmap

Potential features for future releases:

- [ ] Drag-and-drop file support (requires `tkinterdnd2`)
- [ ] Custom output directory selection in UI
- [ ] Multi-language support
- [ ] Dark theme option
- [ ] File size information before operations
- [ ] Estimated time remaining for operations
- [ ] Pak file comparison tool
- [ ] Integration with STALKER 2 mod managers
- [ ] Auto-update checker
- [ ] Plugin system for custom operations

---

**Note**: Dates will be filled in upon actual release.
