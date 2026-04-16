# Development

## Run
```bash
python3 repak_gui.py
# Or on Linux:
./run.sh
```

## Tests (90 total)
```bash
python3 -m pytest test_repak_gui.py -v
# With coverage:
python3 -m pytest test_repak_gui.py -v --cov=repak_gui --cov=find_conflicts
```

Categories: AESKeyValidation, RedactAESKey, PathValidation, ConfigPersistence, RecentFilesLimit, FindConflicts, VersionComparison, Constants, CopyConflictsToFolders, AESKeyEdgeCases, PathValidationEdgeCases, GitHubConstants, UIConstants, AESKeyPatterns, FindConflictsEdgeCases, OutputFolder

## Dependencies
All stdlib: `tkinter`, `subprocess`, `threading`, `json`, `logging`, `re`, `hashlib`
Dev: `pytest`, `pytest-cov`, `ruff`

## CI
- `test.yml` — pytest + ruff lint on push/PR
- `build-release.yml` — PyInstaller builds + GitHub Release on tag
- `security-scan.yml` — dangerous pattern detection on PR
- `codeql.yml` — CodeQL analysis

## Platform Notes
- Windows: `repak.exe` in script dir, needs `oo2core_9_win64.dll`
- Linux: `repak` binary in script dir, tkinter via package manager
