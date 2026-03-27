# Configuration

Config path: `./repak_gui_config.json` (script directory — intentional for portability)

## Settings
- `repak_path` — path to repak binary
- `last_input_dir`, `last_output_dir`
- `aes_key` — saved AES key
- `recent_files` — list (max 10)
- `auto_check_updates` — startup check (default: true)
- `window_geometry`

## Logging
File: `./repak_gui.log` — RotatingFileHandler, 5MB max, 3 backups
Format: `%(asctime)s - %(levelname)s - %(message)s`
