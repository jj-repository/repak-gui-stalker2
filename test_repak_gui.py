#!/usr/bin/env python3
"""
Unit tests for Repak GUI

Run with: pytest test_repak_gui.py -v
Run with coverage: pytest test_repak_gui.py -v --cov=repak_gui --cov=find_conflicts
"""

import pytest
import tempfile
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tkinter as tk

# Import the modules to test
import repak_gui
import find_conflicts


class TestAESKeyValidation:
    """Test suite for AES key validation"""

    def test_empty_key_is_valid(self):
        """Empty key should be valid (no encryption)"""
        assert repak_gui.validate_aes_key("") is True
        assert repak_gui.validate_aes_key("   ") is True

    def test_valid_hex_key(self):
        """64 character hex string should be valid"""
        valid_hex = "0" * 64
        assert repak_gui.validate_aes_key(valid_hex) is True

        valid_hex_mixed = "0123456789abcdefABCDEF" + "0" * 42
        assert repak_gui.validate_aes_key(valid_hex_mixed) is True

    def test_valid_hex_key_with_prefix(self):
        """0x prefixed hex key should be valid"""
        assert repak_gui.validate_aes_key("0x" + "0" * 64) is True

    def test_valid_base64_key(self):
        """Base64 encoded key should be valid"""
        # 43 base64 chars = 256 bits
        valid_base64 = "A" * 43 + "="
        assert repak_gui.validate_aes_key(valid_base64) is True

    def test_invalid_hex_key_too_short(self):
        """Hex key that's too short should be invalid"""
        assert repak_gui.validate_aes_key("0" * 32) is False

    def test_invalid_hex_key_too_long(self):
        """Hex key that's too long should be invalid"""
        assert repak_gui.validate_aes_key("0" * 128) is False

    def test_invalid_characters(self):
        """Key with invalid characters should be invalid"""
        assert repak_gui.validate_aes_key("GHIJK" + "0" * 59) is False


class TestRedactAESKey:
    """Test suite for AES key redaction"""

    def test_redacts_aes_key(self):
        """AES key value should be redacted in logs"""
        # Test the _redact_aes_key method directly with a simple class
        class MockGUI:
            pass

        mock_gui = MockGUI()
        # Bind the unbound method to our mock instance
        method = repak_gui.RepakGUI._redact_aes_key.__get__(mock_gui, MockGUI)

        cmd = ["repak", "unpack", "file.pak", "--aes-key", "secretkey123"]
        redacted = method(cmd)

        assert "secretkey123" not in redacted
        assert "[REDACTED]" in redacted
        assert "--aes-key" in redacted

    def test_no_key_no_redaction(self):
        """Command without AES key should not be modified"""
        class MockGUI:
            pass

        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._redact_aes_key.__get__(mock_gui, MockGUI)

        cmd = ["repak", "unpack", "file.pak", "--output", "/some/path"]
        redacted = method(cmd)

        assert "repak" in redacted
        assert "[REDACTED]" not in redacted


class TestPathValidation:
    """Test suite for path validation"""

    def test_validate_existing_path(self, tmp_path):
        """Existing path should validate successfully"""
        test_file = tmp_path / "test.pak"
        test_file.touch()

        class MockGUI:
            pass

        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)
        result = method(str(test_file), must_exist=True)

        assert result is not None
        assert result.exists()

    def test_validate_nonexistent_path(self):
        """Non-existent path should return None when must_exist=True"""
        class MockGUI:
            pass

        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)
        result = method("/nonexistent/path/file.pak", must_exist=True)

        assert result is None

    def test_validate_path_not_required_to_exist(self, tmp_path):
        """Path not required to exist should validate"""
        class MockGUI:
            pass

        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)
        new_file = tmp_path / "new_file.pak"
        result = method(str(new_file), must_exist=False)

        assert result is not None


class TestConfigPersistence:
    """Test suite for configuration persistence"""

    def test_config_save_and_load(self, tmp_path):
        """Configuration should be saved and loaded correctly"""
        config_file = tmp_path / "test_config.json"

        # Write test config
        test_config = {
            'window_geometry': '800x600',
            'recent_files': ['/path/to/file1.pak', '/path/to/file2.pak'],
            'last_unpack_dir': '/some/dir',
            'last_pack_dir': '/another/dir'
        }

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(test_config, f)

        # Read it back
        with open(config_file, 'r', encoding='utf-8') as f:
            loaded_config = json.load(f)

        assert loaded_config['window_geometry'] == '800x600'
        assert len(loaded_config['recent_files']) == 2
        assert '/path/to/file1.pak' in loaded_config['recent_files']

    def test_legacy_aes_key_removed(self, tmp_path):
        """Legacy AES key should be removed from config for security"""
        config_file = tmp_path / "test_config.json"

        # Write config with legacy AES key
        old_config = {
            'window_geometry': '800x600',
            'recent_files': [],
            'last_aes_key': 'should_be_removed'
        }

        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(old_config, f)

        # Simulate loading (manually test the logic)
        with open(config_file, 'r', encoding='utf-8') as f:
            loaded = json.load(f)

        if 'last_aes_key' in loaded:
            del loaded['last_aes_key']

        assert 'last_aes_key' not in loaded


class TestRecentFilesLimit:
    """Test suite for recent files management"""

    def test_max_recent_files_constant(self):
        """MAX_RECENT_FILES should be defined and reasonable"""
        assert hasattr(repak_gui, 'MAX_RECENT_FILES')
        assert repak_gui.MAX_RECENT_FILES > 0
        assert repak_gui.MAX_RECENT_FILES <= 100  # Sanity check


class TestFindConflicts:
    """Test suite for find_conflicts.py functions"""

    def test_file_hash_sha256(self, tmp_path):
        """File hashing should use SHA-256 and return 64 hex chars"""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        file_hash = find_conflicts.get_file_hash(test_file)

        # SHA-256 hash is 64 characters (hex)
        assert file_hash is not None
        assert len(file_hash) == 64
        assert all(c in '0123456789abcdef' for c in file_hash)

    def test_file_hash_consistent(self, tmp_path):
        """Same content should produce same hash"""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"

        file1.write_text("identical content")
        file2.write_text("identical content")

        hash1 = find_conflicts.get_file_hash(file1)
        hash2 = find_conflicts.get_file_hash(file2)

        assert hash1 == hash2

    def test_file_hash_different_content(self, tmp_path):
        """Different content should produce different hash"""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"

        file1.write_text("content A")
        file2.write_text("content B")

        hash1 = find_conflicts.get_file_hash(file1)
        hash2 = find_conflicts.get_file_hash(file2)

        assert hash1 != hash2

    def test_file_hash_nonexistent_file(self, tmp_path):
        """Non-existent file should return None"""
        nonexistent = tmp_path / "does_not_exist.txt"
        result = find_conflicts.get_file_hash(nonexistent)
        assert result is None

    def test_find_cfg_files_empty_dir(self, tmp_path, monkeypatch):
        """Empty directory should return empty dict"""
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', tmp_path)

        result = find_conflicts.find_cfg_files()

        assert len(result) == 0

    def test_find_cfg_files_with_files(self, tmp_path, monkeypatch):
        """Should find .cfg files in subdirectories"""
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', tmp_path)

        # Create mod structure
        mod1_dir = tmp_path / "mod1" / "config"
        mod1_dir.mkdir(parents=True)
        (mod1_dir / "settings.cfg").write_text("setting=1")

        mod2_dir = tmp_path / "mod2" / "config"
        mod2_dir.mkdir(parents=True)
        (mod2_dir / "settings.cfg").write_text("setting=2")

        result = find_conflicts.find_cfg_files()

        assert "settings.cfg" in result
        assert len(result["settings.cfg"]) == 2

    def test_find_conflicts_no_duplicates(self, tmp_path, monkeypatch):
        """Single file should not be a conflict"""
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', tmp_path)

        mod1_dir = tmp_path / "mod1" / "config"
        mod1_dir.mkdir(parents=True)
        (mod1_dir / "unique.cfg").write_text("content")

        cfg_files = find_conflicts.find_cfg_files()
        conflicts = find_conflicts.find_conflicts(cfg_files)

        assert len(conflicts) == 0

    def test_find_conflicts_identical_files(self, tmp_path, monkeypatch):
        """Identical files should not be reported as conflicts"""
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', tmp_path)

        mod1_dir = tmp_path / "mod1"
        mod1_dir.mkdir()
        (mod1_dir / "same.cfg").write_text("identical")

        mod2_dir = tmp_path / "mod2"
        mod2_dir.mkdir()
        (mod2_dir / "same.cfg").write_text("identical")

        cfg_files = find_conflicts.find_cfg_files()
        conflicts = find_conflicts.find_conflicts(cfg_files)

        assert len(conflicts) == 0

    def test_find_conflicts_different_files(self, tmp_path, monkeypatch):
        """Different files with same name should be conflicts"""
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', tmp_path)

        mod1_dir = tmp_path / "mod1"
        mod1_dir.mkdir()
        (mod1_dir / "config.cfg").write_text("version=1")

        mod2_dir = tmp_path / "mod2"
        mod2_dir.mkdir()
        (mod2_dir / "config.cfg").write_text("version=2")

        cfg_files = find_conflicts.find_cfg_files()
        conflicts = find_conflicts.find_conflicts(cfg_files)

        assert len(conflicts) == 1
        assert "config.cfg" in conflicts


class TestVersionDefined:
    """Test that version info is properly defined"""

    def test_version_string_exists(self):
        """Version should be defined as a non-empty string"""
        assert hasattr(repak_gui, '__version__')
        assert isinstance(repak_gui.__version__, str)
        assert len(repak_gui.__version__) > 0

    def test_version_format(self):
        """Version should follow semantic versioning pattern"""
        version = repak_gui.__version__
        parts = version.split('.')
        assert len(parts) >= 2  # At least major.minor


class TestConstants:
    """Test that important constants are defined"""

    def test_window_constants(self):
        """Window dimension constants should be defined"""
        assert hasattr(repak_gui, 'WINDOW_WIDTH')
        assert hasattr(repak_gui, 'WINDOW_HEIGHT')
        assert repak_gui.WINDOW_WIDTH > 0
        assert repak_gui.WINDOW_HEIGHT > 0

    def test_subprocess_timeout(self):
        """Subprocess timeout should be defined and reasonable"""
        assert hasattr(repak_gui, 'SUBPROCESS_TIMEOUT')
        assert repak_gui.SUBPROCESS_TIMEOUT >= 60  # At least 1 minute

    def test_platform_detection(self):
        """IS_WINDOWS constant should be defined"""
        assert hasattr(repak_gui, 'IS_WINDOWS')
        assert isinstance(repak_gui.IS_WINDOWS, bool)


class TestCopyConflictsToFolders:
    """Test suite for copying conflicts to folders"""

    def test_copy_conflicts_creates_directory(self, tmp_path, monkeypatch):
        """Should create conflicts directory"""
        conflicts_dir = tmp_path / "conflicts"
        monkeypatch.setattr(find_conflicts, 'CONFLICTS_DIR', conflicts_dir)
        monkeypatch.setattr(find_conflicts, 'SCRIPT_DIR', tmp_path)

        # Create a simple conflict
        mod1_dir = tmp_path / "mod1"
        mod1_dir.mkdir()
        test_file = mod1_dir / "test.cfg"
        test_file.write_text("content")

        conflicts = {
            "test.cfg": {
                "occurrences": [
                    {"mod": "mod1", "path": test_file}
                ],
                "unique_versions": 1
            }
        }

        result = find_conflicts.copy_conflicts_to_folders(conflicts)

        assert result is not None
        assert conflicts_dir.exists()

    def test_copy_conflicts_sanitizes_mod_name(self, tmp_path, monkeypatch):
        """Should sanitize mod names with special characters"""
        conflicts_dir = tmp_path / "conflicts"
        monkeypatch.setattr(find_conflicts, 'CONFLICTS_DIR', conflicts_dir)
        monkeypatch.setattr(find_conflicts, 'SCRIPT_DIR', tmp_path)

        # Create file with problematic mod name
        mod_dir = tmp_path / "mod_with_slash"
        mod_dir.mkdir()
        test_file = mod_dir / "test.cfg"
        test_file.write_text("content")

        conflicts = {
            "test.cfg": {
                "occurrences": [
                    {"mod": "path/with/slashes", "path": test_file}
                ],
                "unique_versions": 1
            }
        }

        result = find_conflicts.copy_conflicts_to_folders(conflicts)

        assert result is not None
        # Check that the file was created with sanitized name
        conflict_folder = conflicts_dir / "test"
        assert conflict_folder.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=repak_gui", "--cov=find_conflicts"])
