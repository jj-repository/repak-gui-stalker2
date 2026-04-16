# Changelog

All notable changes to Repak GUI will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows X.YY display format (see CLAUDE.md).

## [1.07] - 2026-04-16

### Added
- Configurable output folder with "Set Output Folder" button
- Default output to ~/Downloads instead of script directory
- "Reset" button to restore default output folder
- Dynamic output path labels update across all tabs

## [1.06] - 2026-04-16

### Changed
- Thread-safe cancellation via `threading.Event` (replaces bare bool)
- SHA-256 as primary update verification, SHA-1 as fallback only
- Lock scoping: hold only for data snapshot, release before I/O
- Counter-based log trimming (check every 500 lines, not per-call)
- Auto-update check disabled by default
- CI: hardened permissions, timeouts, pip caching

### Fixed
- `_sha256sums_cache` properly initialized in `__init__`
- Deduplicated do_info/do_list into `_do_pak_query()`

## [1.05] - 2026-03-28

### Changed
- Switched to X.YY versioning (from semver)
- Standardized CLAUDE.md format across repos

## [1.4.5] - 2026-01-15

### Added
- SHA-256 verification for self-update (release SHA256SUMS + git blob SHA-1)
- CI: security-scan and doc-review workflows

### Changed
- CI: replaced softprops/action-gh-release with `gh release create`
- Standardized release artifact naming to `RepakGUI-{OS}`

### Fixed
- Git blob SHA verification for update integrity

## [1.4.3] - 2026-01-02

### Fixed
- Windows compatibility and thread safety
- Race condition in `cancel_operation()` with lock protection

## [1.2.0] - 2026-01-01

### Added
- AES key validation (64-char hex or base64) with user warnings
- Batch unpack cancellation via Escape/Cancel button
- Subprocess timeout (1 hour) prevents hanging operations
- Windows support: `repak.exe` detection, `CREATE_NO_WINDOW` flag
- Thread safety lock for shared state

### Security
- Removed plaintext AES key storage from config
- Auto-removes legacy `last_aes_key` on config load

### Fixed
- Subprocess resource leaks (explicit stdout.close, proper cleanup)
- Specific exception handling replacing broad `except Exception`
- Zombie processes on cancellation
- Log file created in wrong directory

## [1.1.0] - 2025-12-28

### Added
- Operation cancellation (Escape key, Cancel button)
- Recent files menu (up to 10 files)
- Keyboard shortcuts: Ctrl+O/L/E/Q, Escape
- Context menu for batch list (remove, clear, reorder)
- File-based logging with rotation (5MB, 3 backups)
- Log export (Ctrl+E)
- Configuration persistence (window geometry, recent files)
- Menu bar (File, Help)
- Type hints throughout codebase
- Unit test suite (pytest)

### Security
- AES key redaction in logs
- Path traversal validation
- Binary integrity checks
- SHA-256 hashing in find_conflicts.py (replaced MD5)
- Directory deletion safety checks

## [1.0.0] - 2025-12-01

### Added
- Initial release
- GUI wrapper for repak (Unreal Engine .pak tool)
- Unpack/Pack .pak files with AES-256 encryption
- Batch unpack multiple files
- Info and List commands
- `find_conflicts.py` for detecting mod conflicts
- GitHub Actions CI/CD (Linux + Windows builds)
- Shell launcher (`run.sh`) for Linux
