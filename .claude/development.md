# Development

## Run
```bash
python repak_gui.py
pip install tkinterdnd2  # optional drag-and-drop
```

## Tests (85 total)
```bash
python -m pytest test_repak_gui.py -v
```
Categories: AESKeyValidation, RedactAESKey, PathValidation, ConfigPersistence, RecentFilesLimit, FindConflicts, VersionDefined, Constants, CopyConflictsToFolders

## Dependencies
All stdlib: `tkinter`, `subprocess`, `threading`, `json`, `logging`, `re`
Optional: `tkinterdnd2`

## Platform Notes
- Windows: `repak.exe` in script dir or PATH, native file dialogs
- Linux: `repak` binary in script dir or PATH; DnD may not work on Wayland without setup
