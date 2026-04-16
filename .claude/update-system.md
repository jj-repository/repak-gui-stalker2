# Update System

## Functions
- `_check_for_updates()` — GitHub API, silent or interactive
- `_version_newer()` — staticmethod, zero-padded tuple compare for X.YY
- `_show_update_dialog()` — Update Now / Open Releases / Later
- `_apply_update()` — download, verify integrity, backup `.py.backup`, replace
- `_compute_git_blob_sha(content)` — `SHA1("blob {len}\0{content}")`
- `_get_expected_sha256()` — fetch SHA256SUMS from release, parse, cache
- `_verify_file_against_github()` — SHA-256 primary, SHA-1 fallback only

## Integrity Chain
1. SHA-256: fetch SHA256SUMS from GitHub Release assets, verify downloaded content
2. SHA-1 (fallback): git blob SHA via GitHub Contents API — only used when SHA256SUMS unavailable
3. `.py.backup` created before replacing the running script

## Defaults
- Auto-check on startup: **disabled** by default
- Manual check: Help menu > Check for Updates

## GitHub
Repo: `jj-repository/repak-gui-stalker2`
