# Overview

v1.05 — tkinter GUI wrapper for `repak` CLI (Unreal Engine .pak). STALKER 2 modding tool. Single-file for easy distribution alongside repak binary.

## Files
- `repak_gui.py` — main app
- `repak_gui.py.sha256` — checksum (regenerate after every edit!)
- `repak_gui_config.json` — generated user config
- `repak_gui.log` — generated log (rotating)
- `repak` / `repak.exe` — expected repak binary (script dir or PATH)

## Features
- Pack folders → .pak, unpack .pak → folders
- AES-256 encryption (hex or base64 keys)
- Batch operations, recent files (max 10)
- Progress indication, cancelable operations
- Path validation and security checks
