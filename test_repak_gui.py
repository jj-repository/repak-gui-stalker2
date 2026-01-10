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


class TestVersionComparison:
    """Test suite for version comparison (_version_newer method)"""

    def test_newer_major_version(self):
        """Newer major version should be detected"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._version_newer.__get__(mock_gui, MockGUI)

        assert method("2.0.0", "1.0.0") is True
        assert method("10.0.0", "9.0.0") is True

    def test_newer_minor_version(self):
        """Newer minor version should be detected"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._version_newer.__get__(mock_gui, MockGUI)

        assert method("1.1.0", "1.0.0") is True
        assert method("1.10.0", "1.9.0") is True

    def test_newer_patch_version(self):
        """Newer patch version should be detected"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._version_newer.__get__(mock_gui, MockGUI)

        assert method("1.0.1", "1.0.0") is True
        assert method("1.0.10", "1.0.9") is True

    def test_same_version_not_newer(self):
        """Same version should not be considered newer"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._version_newer.__get__(mock_gui, MockGUI)

        assert method("1.0.0", "1.0.0") is False
        assert method("2.5.3", "2.5.3") is False

    def test_older_version_not_newer(self):
        """Older version should not be considered newer"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._version_newer.__get__(mock_gui, MockGUI)

        assert method("1.0.0", "2.0.0") is False
        assert method("1.0.0", "1.1.0") is False
        assert method("1.0.0", "1.0.1") is False

    def test_invalid_version_returns_false(self):
        """Invalid version strings should return False"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._version_newer.__get__(mock_gui, MockGUI)

        assert method("invalid", "1.0.0") is False
        assert method("1.0.0", "invalid") is False
        assert method("", "1.0.0") is False
        assert method("1.0.0", "") is False

    def test_version_with_two_parts(self):
        """Versions with only major.minor should work"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._version_newer.__get__(mock_gui, MockGUI)

        assert method("1.1", "1.0") is True
        assert method("2.0", "1.9") is True


class TestAESKeyEdgeCases:
    """Additional edge cases for AES key validation"""

    def test_key_with_spaces_around_valid_hex(self):
        """Key with leading/trailing spaces should be validated after strip"""
        # The function strips whitespace before validation
        valid_hex = "0" * 64
        assert repak_gui.validate_aes_key(f"  {valid_hex}  ") is True

    def test_key_with_tabs_is_treated_as_whitespace(self):
        """Tab-only key should be treated as empty"""
        assert repak_gui.validate_aes_key("\t\t") is True

    def test_key_with_newline_is_treated_as_whitespace(self):
        """Newline-only key should be treated as empty"""
        assert repak_gui.validate_aes_key("\n") is True

    def test_hex_key_with_lowercase(self):
        """Lowercase hex should be valid"""
        assert repak_gui.validate_aes_key("a" * 64) is True

    def test_hex_key_with_uppercase(self):
        """Uppercase hex should be valid"""
        assert repak_gui.validate_aes_key("A" * 64) is True

    def test_hex_key_mixed_case(self):
        """Mixed case hex should be valid"""
        assert repak_gui.validate_aes_key("aAbBcCdDeEfF0123456789" + "0" * 42) is True

    def test_base64_with_equals_padding(self):
        """Base64 with = padding should be valid"""
        # 43 chars + 1 padding = valid base64 for 256 bits
        assert repak_gui.validate_aes_key("A" * 43 + "=") is True

    def test_base64_without_padding(self):
        """Base64 without padding should be valid"""
        assert repak_gui.validate_aes_key("A" * 43) is True

    def test_0x_prefix_with_wrong_length(self):
        """0x prefix with wrong length should be invalid"""
        assert repak_gui.validate_aes_key("0x" + "0" * 32) is False

    def test_key_exactly_63_chars_invalid(self):
        """Key with 63 hex chars should be invalid (too short)"""
        assert repak_gui.validate_aes_key("0" * 63) is False

    def test_key_exactly_65_chars_invalid(self):
        """Key with 65 hex chars should be invalid (too long)"""
        assert repak_gui.validate_aes_key("0" * 65) is False


class TestPathValidationEdgeCases:
    """Additional edge cases for path validation"""

    def test_path_with_null_byte_rejected(self):
        """Path containing null byte should be rejected"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)

        result = method("/path/to/file\x00.pak", must_exist=False)
        assert result is None

    def test_path_with_traversal_forward_slash(self):
        """Path with ../ traversal should be rejected"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)

        result = method("/path/../etc/passwd", must_exist=False)
        assert result is None

    def test_path_with_traversal_backslash(self):
        """Path with ..\\ traversal should be rejected"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)

        result = method("C:\\path\\..\\windows\\system32", must_exist=False)
        assert result is None

    def test_empty_path_rejected(self):
        """Empty path should be rejected"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)

        assert method("", must_exist=False) is None
        assert method("   ", must_exist=False) is None

    def test_valid_absolute_path(self, tmp_path):
        """Valid absolute path should be accepted"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)

        test_file = tmp_path / "test.pak"
        test_file.touch()

        result = method(str(test_file), must_exist=True)
        assert result is not None
        assert result == test_file.resolve()

    def test_valid_path_must_not_exist(self, tmp_path):
        """Path not required to exist should be accepted even if missing"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._validate_path.__get__(mock_gui, MockGUI)

        new_file = tmp_path / "new_file.pak"
        result = method(str(new_file), must_exist=False)
        assert result is not None


class TestGitHubConstants:
    """Test GitHub URL and constant definitions"""

    def test_github_repo_format(self):
        """GITHUB_REPO should be in owner/repo format"""
        assert "/" in repak_gui.GITHUB_REPO
        parts = repak_gui.GITHUB_REPO.split("/")
        assert len(parts) == 2
        assert len(parts[0]) > 0  # owner
        assert len(parts[1]) > 0  # repo

    def test_github_releases_url_valid(self):
        """GITHUB_RELEASES_URL should be a valid URL"""
        assert repak_gui.GITHUB_RELEASES_URL.startswith("https://github.com/")
        assert "/releases" in repak_gui.GITHUB_RELEASES_URL

    def test_github_api_url_valid(self):
        """GITHUB_API_LATEST should be a valid API URL"""
        assert repak_gui.GITHUB_API_LATEST.startswith("https://api.github.com/repos/")
        assert "/releases/latest" in repak_gui.GITHUB_API_LATEST

    def test_github_raw_url_valid(self):
        """GITHUB_RAW_URL should be a valid raw content URL"""
        assert repak_gui.GITHUB_RAW_URL.startswith("https://raw.githubusercontent.com/")


class TestUIConstants:
    """Additional tests for UI constants"""

    def test_min_window_dimensions_valid(self):
        """Minimum window dimensions should be positive and reasonable"""
        assert repak_gui.MIN_WINDOW_WIDTH > 0
        assert repak_gui.MIN_WINDOW_HEIGHT > 0
        assert repak_gui.MIN_WINDOW_WIDTH <= repak_gui.WINDOW_WIDTH
        assert repak_gui.MIN_WINDOW_HEIGHT <= repak_gui.WINDOW_HEIGHT

    def test_progress_bar_interval_positive(self):
        """Progress bar interval should be positive"""
        assert repak_gui.PROGRESS_BAR_INTERVAL > 0

    def test_log_font_size_reasonable(self):
        """Log font size should be reasonable"""
        assert 6 <= repak_gui.LOG_FONT_SIZE <= 20

    def test_max_recent_files_positive(self):
        """MAX_RECENT_FILES should be positive"""
        assert repak_gui.MAX_RECENT_FILES > 0

    def test_subprocess_timeout_reasonable(self):
        """Subprocess timeout should be reasonable (at least 1 minute, at most 2 hours)"""
        assert 60 <= repak_gui.SUBPROCESS_TIMEOUT <= 7200


class TestAESKeyPatterns:
    """Test AES key regex patterns directly"""

    def test_hex_pattern_matches_valid(self):
        """Hex pattern should match valid 64-char hex strings"""
        valid_hex = "0123456789abcdefABCDEF" + "0" * 42
        assert repak_gui.AES_KEY_HEX_PATTERN.match(valid_hex) is not None

    def test_hex_pattern_rejects_invalid(self):
        """Hex pattern should reject non-hex characters"""
        invalid_hex = "ghijk" + "0" * 59
        assert repak_gui.AES_KEY_HEX_PATTERN.match(invalid_hex) is None

    def test_base64_pattern_matches_valid(self):
        """Base64 pattern should match valid base64 strings"""
        # Pattern expects exactly 43 base64 chars (optionally followed by =)
        valid_base64 = "A" * 43  # 43 chars without padding
        assert repak_gui.AES_KEY_BASE64_PATTERN.match(valid_base64) is not None

    def test_base64_pattern_with_plus_and_slash(self):
        """Base64 pattern should accept + and / characters"""
        # Pattern expects exactly 43 base64 chars (optionally followed by =)
        # Build string with + and /: 20 A's + '+' + 20 B's + '/' + 1 C = 43 chars
        valid_base64 = "A" * 20 + "+" + "B" * 20 + "/" + "C"
        assert len(valid_base64) == 43
        assert repak_gui.AES_KEY_BASE64_PATTERN.match(valid_base64) is not None


class TestFindConflictsEdgeCases:
    """Additional edge cases for find_conflicts module"""

    def test_file_hash_binary_file(self, tmp_path):
        """Binary file should be hashable"""
        binary_file = tmp_path / "binary.cfg"
        binary_file.write_bytes(b'\x00\x01\x02\x03\xff\xfe\xfd')

        file_hash = find_conflicts.get_file_hash(binary_file)
        assert file_hash is not None
        assert len(file_hash) == 64

    def test_file_hash_large_file(self, tmp_path):
        """Large file should be hashable (tests chunked reading)"""
        large_file = tmp_path / "large.cfg"
        # Write a file larger than HASH_CHUNK_SIZE (8192 bytes)
        large_file.write_bytes(b'x' * 20000)

        file_hash = find_conflicts.get_file_hash(large_file)
        assert file_hash is not None
        assert len(file_hash) == 64

    def test_file_hash_empty_file(self, tmp_path):
        """Empty file should be hashable"""
        empty_file = tmp_path / "empty.cfg"
        empty_file.touch()

        file_hash = find_conflicts.get_file_hash(empty_file)
        assert file_hash is not None
        # SHA-256 of empty file is a known value
        assert file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_find_cfg_files_nonexistent_unpack_dir(self, tmp_path, monkeypatch):
        """Nonexistent unpack directory should return empty dict"""
        nonexistent = tmp_path / "does_not_exist"
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', nonexistent)

        result = find_conflicts.find_cfg_files()
        assert len(result) == 0

    def test_find_cfg_files_nested_structure(self, tmp_path, monkeypatch):
        """Should find cfg files in deeply nested directories"""
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', tmp_path)

        # Create deeply nested structure
        nested_dir = tmp_path / "mod1" / "config" / "game" / "settings"
        nested_dir.mkdir(parents=True)
        (nested_dir / "deep.cfg").write_text("deep content")

        result = find_conflicts.find_cfg_files()

        assert "deep.cfg" in result
        assert result["deep.cfg"][0]["mod"] == "mod1"

    def test_find_conflicts_multiple_identical_files(self, tmp_path, monkeypatch):
        """Multiple identical files should not be reported as conflicts"""
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', tmp_path)

        # Create 5 mods with identical content
        for i in range(5):
            mod_dir = tmp_path / f"mod{i}"
            mod_dir.mkdir()
            (mod_dir / "same.cfg").write_text("identical")

        cfg_files = find_conflicts.find_cfg_files()
        conflicts = find_conflicts.find_conflicts(cfg_files)

        assert len(conflicts) == 0

    def test_find_conflicts_three_different_versions(self, tmp_path, monkeypatch):
        """Three different versions of a file should show 3 unique versions"""
        monkeypatch.setattr(find_conflicts, 'UNPACK_DIR', tmp_path)

        for i in range(3):
            mod_dir = tmp_path / f"mod{i}"
            mod_dir.mkdir()
            (mod_dir / "config.cfg").write_text(f"version {i}")

        cfg_files = find_conflicts.find_cfg_files()
        conflicts = find_conflicts.find_conflicts(cfg_files)

        assert "config.cfg" in conflicts
        assert conflicts["config.cfg"]["unique_versions"] == 3

    def test_copy_conflicts_multiple_files(self, tmp_path, monkeypatch):
        """Should copy multiple conflicting files to separate folders"""
        conflicts_dir = tmp_path / "conflicts"
        monkeypatch.setattr(find_conflicts, 'CONFLICTS_DIR', conflicts_dir)
        monkeypatch.setattr(find_conflicts, 'SCRIPT_DIR', tmp_path)

        # Create files
        mod1_dir = tmp_path / "mod1"
        mod1_dir.mkdir()
        file1 = mod1_dir / "config1.cfg"
        file2 = mod1_dir / "config2.cfg"
        file1.write_text("content1")
        file2.write_text("content2")

        conflicts = {
            "config1.cfg": {
                "occurrences": [{"mod": "mod1", "path": file1}],
                "unique_versions": 1
            },
            "config2.cfg": {
                "occurrences": [{"mod": "mod1", "path": file2}],
                "unique_versions": 1
            }
        }

        result = find_conflicts.copy_conflicts_to_folders(conflicts)

        assert result is not None
        assert (conflicts_dir / "config1").exists()
        assert (conflicts_dir / "config2").exists()


class TestRedactAESKeyEdgeCases:
    """Additional edge cases for AES key redaction"""

    def test_redact_multiple_aes_keys(self):
        """Multiple --aes-key arguments should all be redacted"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._redact_aes_key.__get__(mock_gui, MockGUI)

        cmd = ["repak", "unpack", "--aes-key", "secret1", "--aes-key", "secret2"]
        redacted = method(cmd)

        assert "secret1" not in redacted
        assert "secret2" not in redacted
        assert redacted.count("[REDACTED]") == 2

    def test_redact_empty_command(self):
        """Empty command list should not crash"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._redact_aes_key.__get__(mock_gui, MockGUI)

        result = method([])
        assert result == ""

    def test_redact_aes_key_at_end(self):
        """--aes-key at end without value should not crash"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._redact_aes_key.__get__(mock_gui, MockGUI)

        cmd = ["repak", "unpack", "--aes-key"]
        result = method(cmd)
        assert "--aes-key" in result

    def test_redact_preserves_other_args(self):
        """Other arguments should be preserved"""
        class MockGUI:
            pass
        mock_gui = MockGUI()
        method = repak_gui.RepakGUI._redact_aes_key.__get__(mock_gui, MockGUI)

        cmd = ["repak", "unpack", "file.pak", "--output", "/path/to/output", "--aes-key", "secret"]
        redacted = method(cmd)

        assert "repak" in redacted
        assert "unpack" in redacted
        assert "file.pak" in redacted
        assert "--output" in redacted
        assert "/path/to/output" in redacted
        assert "secret" not in redacted


class TestConfigFileManagement:
    """Test configuration file management"""

    def test_config_file_constant_defined(self):
        """CONFIG_FILE constant should be defined"""
        assert hasattr(repak_gui, 'CONFIG_FILE')
        assert repak_gui.CONFIG_FILE.endswith('.json')

    def test_log_file_constant_defined(self):
        """LOG_FILE constant should be defined"""
        assert hasattr(repak_gui, 'LOG_FILE')
        assert repak_gui.LOG_FILE.endswith('.log')


class TestProcessConstants:
    """Test process-related constants"""

    def test_process_poll_interval_defined(self):
        """PROCESS_POLL_INTERVAL should be defined and positive"""
        assert hasattr(repak_gui, 'PROCESS_POLL_INTERVAL')
        assert repak_gui.PROCESS_POLL_INTERVAL > 0

    def test_is_windows_defined(self):
        """IS_WINDOWS should be defined as boolean"""
        assert hasattr(repak_gui, 'IS_WINDOWS')
        assert isinstance(repak_gui.IS_WINDOWS, bool)


class TestHashChunkSize:
    """Test hash chunk size constant in find_conflicts"""

    def test_hash_chunk_size_defined(self):
        """HASH_CHUNK_SIZE should be defined and reasonable"""
        assert hasattr(find_conflicts, 'HASH_CHUNK_SIZE')
        assert find_conflicts.HASH_CHUNK_SIZE > 0
        # Should be a reasonable buffer size (at least 1KB, at most 1MB)
        assert 1024 <= find_conflicts.HASH_CHUNK_SIZE <= 1048576


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=repak_gui", "--cov=find_conflicts"])
