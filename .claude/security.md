# Security

## Path Validation (`_validate_path()`)
Rejects: null bytes, traversal patterns, non-existent paths. Returns canonicalized absolute path or None.

## AES Key Validation
- Hex: 64 chars (256-bit), with or without 0x prefix
- Base64: 43-44 chars
- Keys redacted in logs via `_redact_aes_key()`
- Keys NOT stored in config (legacy `last_aes_key` auto-removed on load)

## Process Management
- 1-hour operation timeout (`SUBPROCESS_TIMEOUT`)
- Cancelable via `threading.Event` (thread-safe)
- Proper cleanup: terminate → wait(5s) → kill on exit/cancel
- `_end_operation()` in finally block prevents UI deadlock

## Thread Safety
- `_cancel_event`: `threading.Event` for cancel signaling (replaces bare bool)
- `_lock`: protects `current_process`, `_operation_in_progress`, `recent_files`
- Config save: lock held only for snapshot, I/O outside lock

## Update Integrity
- SHA-256 from release SHA256SUMS (primary)
- Git blob SHA-1 via Contents API (fallback when SHA256SUMS unavailable)
- Backup created before replacing script

## Review (2026-04-16)
86/86 tests passing. Thread safety audit complete (threading.Event, lock scoping).
