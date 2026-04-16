# Update System

## Functions
- `_check_for_updates()` — GitHub API, silent or interactive, guarded by `_update_in_progress`
- `_version_newer()` — staticmethod, zero-padded tuple compare for X.YY
- `_show_update_dialog()` — Update Now / Open Releases / Later
- `_apply_update()` — download, verify SHA-256, backup `.py.backup`, replace. Guarded by `_update_in_progress`
- `_get_expected_sha256()` — fetch SHA256SUMS from release, parse, cache
- `_verify_file_against_github()` — SHA-256 only (refuses update if SHA256SUMS unavailable)

## Integrity Chain
1. SHA-256: fetch SHA256SUMS from GitHub Release assets, verify downloaded content
2. Update **refused** if SHA256SUMS not available (no SHA-1 fallback)
3. `.py.backup` created before replacing the running script

## Defaults
- Auto-check on startup: **disabled** by default
- Manual check: Help menu > Check for Updates

## GitHub
Repo: `jj-repository/repak-gui-stalker2`
