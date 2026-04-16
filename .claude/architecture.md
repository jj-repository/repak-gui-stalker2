# Architecture

Single-file: `RepakGUI` class — all UI and logic.

## Components
- Process management: subprocess for repak operations, threaded with cancel support
- Logging: RotatingFileHandler, 5MB limit, 3 backups
- Thread safety: `threading.Event` for cancellation, `threading.Lock` for shared state
- Operation guard: `_try_start_operation()` / `_end_operation()` atomic pattern

## Key Methods
- `run_repak()` — single subprocess execution with cancel/timeout
- `do_batch_unpack()` — sequential multi-pak unpack with per-file progress
- `_do_pak_query()` — shared logic for do_info/do_list
- `_verify_file_against_github()` — SHA-256 primary, SHA-1 fallback

## UI Constants
```python
WINDOW_WIDTH = 700; WINDOW_HEIGHT = 500
MIN_WINDOW_WIDTH = 600; MIN_WINDOW_HEIGHT = 400
LOG_FONT_SIZE = 9; MAX_LOG_LINES = 5000
```
