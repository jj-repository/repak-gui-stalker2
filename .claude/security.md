# Security

## Path Validation (`_validate_path()`)
Rejects: null bytes, non-existent paths, symlink escapes. Returns canonicalized absolute path or None.

## AES Key Validation
- Hex: 64 chars (256-bit)
- Base64: 43-44 chars
- Keys redacted in logs

## Process Management
- 1-hour operation timeout
- Cancelable, proper cleanup on exit
- Lock-protected `current_process` assignments (safe cancellation)

## Thread Safety
- `_try_start_operation()` / `_end_operation()` atomic pattern
- Lock-protected config saves
- Update verification from disk (not memory)

## Review (2026-01-10 — Production Ready)
Path validation, AES validation, key redaction, no command injection, SHA256 for updates, backup before replace, disk verification, atomic operation pattern, config/process locks ✓
85/85 tests passing ✓
