# Decisions & Standards

## Design Decisions
| Decision | Rationale |
|----------|-----------|
| Single-file | Drop alongside repak binary; simple distribution |
| Config in script dir | Portable; users expect self-contained tool |
| 1-hour timeout | Large pak files take time |
| Optional tkinterdnd2 | Graceful degradation if not installed |
| Recent files max 10 | Enough convenience, no bloat |

## Won't Fix
| Issue | Reason |
|-------|--------|
| Config in script dir | Intentional portability |
| DnD not wired | tkinterdnd2 imported but incomplete; low priority |
| No per-file progress bars | Single label sufficient; batch shows count |

## Known Issues
1. Config should use `~/.config/repak-gui/` — intentionally not fixed (portability)
2. Drag-and-drop imported but not wired up

## Recent Fixes (Jan 2026)
`root.after()` dict arg fix, lock on `current_process`, empty pak name validation, zombie process leak on Unix (wait+kill fallback) ✓

## Quality Standards
Target: reliable STALKER 2 modding tool.
Do not optimize: pack/unpack speed = repak binary + disk I/O.

Version bumps default to **+0.0.1** unless told otherwise. Each component 0–9; rollover on overflow (0.0.9 → 0.1.0).
