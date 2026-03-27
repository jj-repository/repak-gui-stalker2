# Update System

Fully implemented with git blob SHA integrity verification.

## Functions
- `_check_for_updates()` — GitHub API
- `_version_newer()` — tuple version compare
- `_show_update_dialog()` — Update Now / Open Releases / Later
- `_apply_update()` — download, verify git blob SHA, backup `.py.backup`, apply
- `_compute_git_blob_sha(content)` — `SHA1("blob {len}\0{content}")`
- `_verify_file_against_github(tag_name, filename, content, headers)` — GitHub Contents API at tag ref

## GitHub
Repo: `jj-repository/repak-gui-stalker2`

## Integrity
- Git blob SHA verified against GitHub Contents API at the release tag ref
- No committed checksum file needed — tag ref is the source of truth
- `.py.backup` created before replace
