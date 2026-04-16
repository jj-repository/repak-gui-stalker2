# Security

## Path Validation (`_validate_path()`)
Rejects: null bytes, traversal patterns, non-existent paths. Returns canonicalized absolute path or None.
Applied to: pak files, source dirs, output folder from config.

## AES Key Validation
- Hex: 64 chars (256-bit), with or without 0x prefix
- Base64: 43-44 chars
- Keys redacted in logs via `_redact_aes_key()`
- Keys NOT stored in config (legacy `last_aes_key` auto-removed on load)

## Process Management
- 1-hour operation timeout (`SUBPROCESS_TIMEOUT`)
- Cancelable via `threading.Event` (thread-safe)
- Proper cleanup: terminate → wait(5s) → kill on exit/cancel
- `_end_operation()` in `run_repak` finally block only (no double-call from callbacks)

## Thread Safety
- `_cancel_event`: `threading.Event` for cancel signaling
- `_lock`: protects `current_process`, `_operation_in_progress`, `recent_files`
- `_update_in_progress`: prevents concurrent update check/apply operations
- Config save: lock held only for snapshot, I/O outside lock
- `root.geometry()` wrapped in TclError catch for close-time safety

## Update Integrity
- SHA-256 from release SHA256SUMS (required)
- Updates refused if SHA256SUMS unavailable (no SHA-1 fallback)
- Backup created before replacing script
- Concurrency guard prevents simultaneous update operations

## Review (2026-04-16)
90/90 tests passing. Thread safety audit + systems review complete.
