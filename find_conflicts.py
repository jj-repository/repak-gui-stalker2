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
    """Get MD5 hash of file contents"""
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

def find_cfg_files():
    """Find all .cfg files and group by filename"""
    cfg_files = defaultdict(list)

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
    # Clean up old conflicts folder
    if CONFLICTS_DIR.exists():
        shutil.rmtree(CONFLICTS_DIR)
    CONFLICTS_DIR.mkdir()

    for filename, info in conflicts.items():
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
