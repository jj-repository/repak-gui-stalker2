# Architecture

Single-file: `RepakGUI` class — all UI and logic.

## Components
- Process management: subprocess for repak operations
- Logging: RotatingFileHandler, 5MB limit, 3 backups
- Drag-and-drop: optional tkinterdnd2 (imported but not wired — known issue)
- Thread safety: `_try_start_operation()` / `_end_operation()` atomic pattern

## Key Methods
- `_run_repak_pack()` — pack operation
- `_run_repak_unpack()` — unpack operation
- `_execute_repak()` — core subprocess execution

## UI Constants
```python
WINDOW_WIDTH = 700; WINDOW_HEIGHT = 500
MIN_WINDOW_WIDTH = 600; MIN_WINDOW_HEIGHT = 400
LOG_FONT_SIZE = 9
```
