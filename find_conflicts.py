#!/usr/bin/env python3
"""
Find conflicting .cfg files across STALKER 2 mods.
Groups files with the same name from different mods into folders for easy comparison.
"""

import sys
import shutil
import hashlib
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional, Any

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
UNPACK_DIR = SCRIPT_DIR / "unpackedfiles"
CONFLICTS_DIR = SCRIPT_DIR / "conflicts"
HASH_CHUNK_SIZE = 8192

def get_file_hash(filepath: Path) -> Optional[str]:
    """
    Get SHA-256 hash of file contents using chunked reading.

    Args:
        filepath: Path to the file to hash

    Returns:
        Hex digest of SHA-256 hash, or None if hashing failed
    """
    hash_obj = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            # Read in chunks to avoid loading entire file into memory
            for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except (IOError, OSError) as e:
        print(f"Warning: Failed to hash {filepath}: {e}", file=sys.stderr)
        return None

def find_cfg_files() -> Dict[str, List[Dict[str, Any]]]:
    """
    Find all .cfg files and group by filename.

    Returns:
        Dictionary mapping filename to list of occurrence dictionaries
    """
    if not UNPACK_DIR.exists():
        print(f"Error: Unpack directory not found: {UNPACK_DIR}", file=sys.stderr)
        return defaultdict(list)

    cfg_files: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    try:
        for cfg_path in UNPACK_DIR.rglob("*.cfg"):
            try:
                # Get the mod name (first folder under unpackedfiles)
                relative = cfg_path.relative_to(UNPACK_DIR)

                # Safety check: ensure relative path has at least one part
                if not relative.parts:
                    print(f"Warning: Skipping file with empty relative path: {cfg_path}", file=sys.stderr)
                    continue

                mod_name = relative.parts[0]

                # Store by filename
                cfg_files[cfg_path.name].append({
                    'path': cfg_path,
                    'mod': mod_name,
                    'relative_path': str(relative)
                })
            except ValueError as e:
                # relative_to can raise ValueError if paths don't match
                print(f"Warning: Skipping {cfg_path}: {e}", file=sys.stderr)
                continue
    except PermissionError as e:
        print(f"Error: Permission denied while scanning: {e}", file=sys.stderr)
    except OSError as e:
        print(f"Error scanning for .cfg files: {e}", file=sys.stderr)

    return cfg_files

def find_conflicts(cfg_files: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """
    Find files that appear in multiple mods with different content.

    Args:
        cfg_files: Dictionary of filename to occurrence list from find_cfg_files()

    Returns:
        Dictionary of conflicting files with their occurrences and unique version count
    """
    conflicts: Dict[str, Dict[str, Any]] = {}

    for filename, occurrences in cfg_files.items():
        if len(occurrences) < 2:
            continue

        # Check if files are actually different (by hash)
        hashes: Dict[str, List[Dict[str, Any]]] = {}
        for occ in occurrences:
            file_hash = get_file_hash(occ['path'])
            if file_hash is None:
                continue  # Skip files that failed to hash
            if file_hash not in hashes:
                hashes[file_hash] = []
            hashes[file_hash].append(occ)

        # If all files are identical (or only one could be hashed), no conflict
        if len(hashes) <= 1:
            continue

        # Real conflict - files differ
        conflicts[filename] = {
            'occurrences': occurrences,
            'unique_versions': len(hashes)
        }

    return conflicts

def copy_conflicts_to_folders(conflicts: Dict[str, Dict[str, Any]]) -> Optional[Path]:
    """
    Copy conflicting files to organized folders for comparison.

    Args:
        conflicts: Dictionary of conflicts from find_conflicts()

    Returns:
        Path to conflicts directory, or None if operation failed
    """
    # Validate CONFLICTS_DIR before deletion
    if CONFLICTS_DIR.exists():
        # Safety check: ensure CONFLICTS_DIR is within expected location
        try:
            conflicts_parent = CONFLICTS_DIR.parent.resolve()
            if conflicts_parent != SCRIPT_DIR:
                print(f"Error: CONFLICTS_DIR is not in expected location. Aborting.", file=sys.stderr)
                return None
            shutil.rmtree(CONFLICTS_DIR)
        except PermissionError as e:
            print(f"Error: Permission denied removing old conflicts directory: {e}", file=sys.stderr)
            return None
        except OSError as e:
            print(f"Error removing old conflicts directory: {e}", file=sys.stderr)
            return None

    try:
        CONFLICTS_DIR.mkdir()
    except PermissionError as e:
        print(f"Error: Permission denied creating conflicts directory: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"Error creating conflicts directory: {e}", file=sys.stderr)
        return None

    copied_count = 0
    error_count = 0

    for filename, info in conflicts.items():
        try:
            # Create folder for this file (remove extension for folder name)
            folder_name = filename.rsplit('.', 1)[0] if '.' in filename else filename
            conflict_folder = CONFLICTS_DIR / folder_name
            conflict_folder.mkdir(exist_ok=True)

            # Copy each version with mod name prefix
            for occ in info['occurrences']:
                # Sanitize mod name for filename (remove path separators and other problematic chars)
                safe_mod_name = occ['mod'].replace('/', '_').replace('\\', '_').replace(':', '_')
                dest_name = f"{safe_mod_name}__{filename}"
                dest_path = conflict_folder / dest_name

                try:
                    shutil.copy2(occ['path'], dest_path)
                    copied_count += 1
                except (IOError, OSError) as e:
                    print(f"Warning: Failed to copy {occ['path']}: {e}", file=sys.stderr)
                    error_count += 1
        except OSError as e:
            print(f"Error processing conflict {filename}: {e}", file=sys.stderr)
            error_count += 1
            continue

    if error_count > 0:
        print(f"Warning: {error_count} file(s) could not be copied", file=sys.stderr)

    return CONFLICTS_DIR

def main() -> int:
    """
    Main entry point for conflict detection.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    print("Scanning for .cfg files...")
    cfg_files = find_cfg_files()

    total_files = sum(len(v) for v in cfg_files.values())
    unique_names = len(cfg_files)
    print(f"Found {total_files} .cfg files ({unique_names} unique names)")

    if total_files == 0:
        print("\nNo .cfg files found. Make sure you have unpacked mods in the 'unpackedfiles' directory.")
        return 0

    print("\nLooking for conflicts (same filename, different content)...")
    conflicts = find_conflicts(cfg_files)

    if not conflicts:
        print("\nNo conflicts found! All duplicate filenames have identical content.")
        return 0

    print(f"\nFound {len(conflicts)} conflicting files:")
    print("-" * 60)

    for filename, info in sorted(conflicts.items()):
        mods = [occ['mod'] for occ in info['occurrences']]
        print(f"\n{filename}")
        print(f"  {info['unique_versions']} different versions across {len(mods)} mods:")
        for mod in mods:
            print(f"    - {mod}")

    print("\n" + "-" * 60)
    print(f"\nCopying conflicts to: {CONFLICTS_DIR}")

    result = copy_conflicts_to_folders(conflicts)
    if result is None:
        print("\nError: Failed to copy conflict files.", file=sys.stderr)
        return 1

    print(f"\nDone! Check the 'conflicts' folder.")
    print("Each subfolder contains all versions of a conflicting file.")
    print("Files are named: MODNAME__originalfilename.cfg")
    return 0


if __name__ == "__main__":
    sys.exit(main())
