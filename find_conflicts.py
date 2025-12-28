#!/usr/bin/env python3
"""
Find conflicting .cfg files across STALKER 2 mods.
Groups files with the same name from different mods into folders for easy comparison.
"""

import os
import shutil
import hashlib
from pathlib import Path
from collections import defaultdict

# Configuration
UNPACK_DIR = Path(__file__).parent / "unpackedfiles"
CONFLICTS_DIR = Path(__file__).parent / "conflicts"

def get_file_hash(filepath):
    """Get SHA-256 hash of file contents (using chunked reading for large files)"""
    hash_obj = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            # Read in chunks to avoid loading entire file into memory
            for chunk in iter(lambda: f.read(8192), b''):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        print(f"Warning: Failed to hash {filepath}: {e}")
        return None

def find_cfg_files():
    """Find all .cfg files and group by filename"""
    if not UNPACK_DIR.exists():
        print(f"Error: Unpack directory not found: {UNPACK_DIR}")
        return defaultdict(list)

    cfg_files = defaultdict(list)

    try:
        for cfg_path in UNPACK_DIR.rglob("*.cfg"):
            # Get the mod name (first folder under unpackedfiles)
            relative = cfg_path.relative_to(UNPACK_DIR)
            mod_name = relative.parts[0]

            # Store by filename
            cfg_files[cfg_path.name].append({
                'path': cfg_path,
                'mod': mod_name,
                'relative_path': str(relative)
            })
    except Exception as e:
        print(f"Error scanning for .cfg files: {e}")

    return cfg_files

def find_conflicts(cfg_files):
    """Find files that appear in multiple mods with different content"""
    conflicts = {}

    for filename, occurrences in cfg_files.items():
        if len(occurrences) < 2:
            continue

        # Check if files are actually different (by hash)
        hashes = {}
        for occ in occurrences:
            file_hash = get_file_hash(occ['path'])
            if file_hash is None:
                continue  # Skip files that failed to hash
            if file_hash not in hashes:
                hashes[file_hash] = []
            hashes[file_hash].append(occ)

        # If all files are identical, no conflict
        if len(hashes) == 1:
            continue

        # Real conflict - files differ
        conflicts[filename] = {
            'occurrences': occurrences,
            'unique_versions': len(hashes)
        }

    return conflicts

def copy_conflicts_to_folders(conflicts):
    """Copy conflicting files to organized folders"""
    # Validate CONFLICTS_DIR before deletion
    if CONFLICTS_DIR.exists():
        # Safety check: ensure CONFLICTS_DIR is within expected location
        try:
            conflicts_parent = CONFLICTS_DIR.parent.resolve()
            script_parent = Path(__file__).parent.resolve()
            if conflicts_parent != script_parent:
                print(f"Error: CONFLICTS_DIR is not in expected location. Aborting.")
                return None
            shutil.rmtree(CONFLICTS_DIR)
        except Exception as e:
            print(f"Error removing old conflicts directory: {e}")
            return None

    try:
        CONFLICTS_DIR.mkdir()
    except Exception as e:
        print(f"Error creating conflicts directory: {e}")
        return None

    for filename, info in conflicts.items():
        try:
            # Create folder for this file
            conflict_folder = CONFLICTS_DIR / filename.replace('.cfg', '')
            conflict_folder.mkdir(exist_ok=True)

            # Copy each version with mod name prefix
            for occ in info['occurrences']:
                # Sanitize mod name for filename
                safe_mod_name = occ['mod'].replace('/', '_').replace('\\', '_')
                dest_name = f"{safe_mod_name}__{filename}"
                dest_path = conflict_folder / dest_name

                shutil.copy2(occ['path'], dest_path)
        except Exception as e:
            print(f"Error processing conflict {filename}: {e}")
            continue

    return CONFLICTS_DIR

def main():
    print("Scanning for .cfg files...")
    cfg_files = find_cfg_files()
    print(f"Found {sum(len(v) for v in cfg_files.values())} .cfg files ({len(cfg_files)} unique names)")

    print("\nLooking for conflicts (same filename, different content)...")
    conflicts = find_conflicts(cfg_files)

    if not conflicts:
        print("\nNo conflicts found! All duplicate filenames have identical content.")
        return

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
    copy_conflicts_to_folders(conflicts)

    print(f"\nDone! Check the 'conflicts' folder.")
    print("Each subfolder contains all versions of a conflicting file.")
    print("Files are named: MODNAME__originalfilename.cfg")

if __name__ == "__main__":
    main()
