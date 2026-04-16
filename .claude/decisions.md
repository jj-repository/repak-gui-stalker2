# Decisions & Standards

## Design Decisions
| Decision | Rationale |
|----------|-----------|
| Single-file | Drop alongside repak binary; simple distribution |
| Config in script dir | Portable; users expect self-contained tool |
| 1-hour timeout | Large pak files take time |
| Recent files max 10 | Enough convenience, no bloat |
| Auto-update off by default | User must opt in; no unsolicited network calls |
| threading.Event for cancel | Thread-safe without explicit lock on every read |

## Won't Fix
| Issue | Reason |
|-------|--------|
| Config in script dir | Intentional portability |
| No per-file progress bars | Single label sufficient; batch shows count |
| Subprocess code duplication | run_repak vs _batch_run — stable, refactor not worth it |
| GPG-signed updates | Overkill for STALKER 2 modding tool |

## Quality Standards
Target: reliable STALKER 2 modding tool.
Do not optimize: pack/unpack speed = repak binary + disk I/O.

Versioning: X.YY display format (see project_versioning.md). Bump minor for features, patch for fixes.
