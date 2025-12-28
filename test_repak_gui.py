#!/usr/bin/env python3
"""
Unit tests for Repak GUI

Run with: pytest test_repak_gui.py -v
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tkinter as tk

# Import the module to test
import repak_gui


class TestRepakGUI:
    """Test suite for RepakGUI class"""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_root(self):
        """Create a mock Tk root"""
        root = Mock(spec=tk.Tk)
        root.geometry = Mock(return_value="800x600+100+100")
        return root

    def test_validate_path_valid(self, temp_dir, mock_root):
        """Test path validation with a valid path"""
        # Create a test file
        test_file = temp_dir / "test.pak"
        test_file.touch()

        with patch('repak_gui.Path.__file__', str(temp_dir / "repak_gui.py")):
            app = repak_gui.RepakGUI(mock_root)
            result = app._validate_path(str(test_file), must_exist=True)
            assert result is not None
            assert result.exists()

    def test_validate_path_nonexistent(self, mock_root):
        """Test path validation with non-existent file"""
        with patch('repak_gui.Path.__file__', "/tmp/repak_gui.py"):
            app = repak_gui.RepakGUI(mock_root)
            result = app._validate_path("/nonexistent/file.pak", must_exist=True)
            assert result is None

    def test_redact_aes_key(self, mock_root):
        """Test AES key redaction in command logging"""
        with patch('repak_gui.Path.__file__', "/tmp/repak_gui.py"):
            app = repak_gui.RepakGUI(mock_root)
            cmd = ["repak", "unpack", "file.pak", "--aes-key", "secretkey123"]
            redacted = app._redact_aes_key(cmd)
            assert "secretkey123" not in redacted
            assert "[REDACTED]" in redacted
            assert "--aes-key" in redacted

    def test_config_persistence(self, temp_dir, mock_root):
        """Test configuration save and load"""
        config_file = temp_dir / "repak_gui_config.json"

        with patch('repak_gui.Path.__file__', str(temp_dir / "repak_gui.py")):
            # Create app and save config
            app = repak_gui.RepakGUI(mock_root)
            app.config_path = config_file
            app.recent_files = ["/path/to/file1.pak", "/path/to/file2.pak"]
            app._save_config()

            # Verify config file was created
            assert config_file.exists()

            # Load config and verify
            with open(config_file, 'r') as f:
                loaded_config = json.load(f)
            assert "recent_files" in loaded_config
            assert len(loaded_config["recent_files"]) == 2

    def test_recent_files_limit(self, mock_root):
        """Test that recent files list respects MAX_RECENT_FILES limit"""
        with patch('repak_gui.Path.__file__', "/tmp/repak_gui.py"):
            app = repak_gui.RepakGUI(mock_root)

            # Add more files than the limit
            for i in range(repak_gui.MAX_RECENT_FILES + 5):
                app._add_to_recent_files(f"/path/to/file{i}.pak")

            # Verify list doesn't exceed limit
            assert len(app.recent_files) <= repak_gui.MAX_RECENT_FILES

    def test_cancel_operation(self, mock_root):
        """Test operation cancellation"""
        with patch('repak_gui.Path.__file__', "/tmp/repak_gui.py"):
            app = repak_gui.RepakGUI(mock_root)
            app.current_process = Mock()
            app.current_process.terminate = Mock()

            app.cancel_operation()

            assert app.cancel_requested == True
            app.current_process.terminate.assert_called_once()


class TestFindConflicts:
    """Test suite for find_conflicts.py functions"""

    def test_file_hash_sha256(self, tmp_path):
        """Test that file hashing uses SHA-256"""
        from find_conflicts import get_file_hash

        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        file_hash = get_file_hash(test_file)

        # SHA-256 hash is 64 characters (hex)
        assert file_hash is not None
        assert len(file_hash) == 64
        assert all(c in '0123456789abcdef' for c in file_hash)


def test_version_defined():
    """Test that version is properly defined"""
    assert hasattr(repak_gui, '__version__')
    assert isinstance(repak_gui.__version__, str)
    assert len(repak_gui.__version__) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=repak_gui", "--cov=find_conflicts"])
