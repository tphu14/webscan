"""
test_config_loader.py - Unit tests for Config Loader
"""
import pytest
import tempfile
from pathlib import Path
from utils.config_loader import load_config


class TestConfigLoader:
    """Test configuration loading and merging"""

    # ==================== DEFAULT CONFIG TESTS ====================

    def test_load_config_returns_dict(self):
        """Test load_config returns dictionary"""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = load_config(str(Path(tmpdir) / "nonexistent.yaml"))
            assert isinstance(result, dict)

    def test_default_config_has_sections(self):
        """Test default config has required sections"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(str(Path(tmpdir) / "nonexistent.yaml"))
            
            assert "scanner" in config
            assert "modules" in config
            assert "detection" in config
            assert "reporting" in config
            assert "logging" in config

    def test_default_scanner_config(self):
        """Test default scanner configuration"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(str(Path(tmpdir) / "nonexistent.yaml"))
            
            scanner = config["scanner"]
            assert scanner["max_depth"] == 3
            assert scanner["max_pages"] == 50
            assert scanner["timeout"] == 10
            assert scanner["concurrency"] == 8

    def test_default_modules_config(self):
        """Test default modules are enabled"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(str(Path(tmpdir) / "nonexistent.yaml"))
            
            modules = config["modules"]
            assert modules["sqli"] is True
            assert modules["xss"] is True
            assert modules["sensitive_files"] is True

    def test_default_detection_config(self):
        """Test default detection configuration"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(str(Path(tmpdir) / "nonexistent.yaml"))
            
            detection = config["detection"]
            assert "confidence_threshold" in detection
            assert "differ_threshold" in detection

    # ==================== FILE LOADING TESTS ====================

    def test_load_existing_config_file(self):
        """Test loading existing config file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "test_config.yaml"
            config_file.write_text("""
scanner:
  max_depth: 5
  timeout: 20
modules:
  sqli: false
""")
            
            config = load_config(str(config_file))
            
            assert config["scanner"]["max_depth"] == 5
            assert config["scanner"]["timeout"] == 20

    def test_merge_config_with_defaults(self):
        """Test user config merges with defaults"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "test.yaml"
            config_file.write_text("""
scanner:
  max_depth: 10
""")
            
            config = load_config(str(config_file))
            
            # User value should override
            assert config["scanner"]["max_depth"] == 10
            # Default value should still exist
            assert config["scanner"]["timeout"] == 10

    def test_load_minimal_config(self):
        """Test loading minimal config file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "minimal.yaml"
            config_file.write_text("scanner:\n  max_pages: 100")
            
            config = load_config(str(config_file))
            
            assert config["scanner"]["max_pages"] == 100
            # Other defaults should exist
            assert config["scanner"]["timeout"] == 10

    def test_load_empty_yaml_file(self):
        """Test loading empty YAML file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "empty.yaml"
            config_file.write_text("")
            
            config = load_config(str(config_file))
            
            # Should have defaults
            assert len(config) > 0
            assert "scanner" in config

    # ==================== EDGE CASES ====================

    def test_nonexistent_file_returns_defaults(self):
        """Test nonexistent config file returns defaults"""
        config = load_config("/nonexistent/path/config.yaml")
        
        assert isinstance(config, dict)
        assert "scanner" in config

    def test_load_config_none_path(self):
        """Test load_config with None path"""
        # Should look for config.yaml in current directory
        config = load_config(None)
        
        assert isinstance(config, dict)

    def test_config_deep_copy_independence(self):
        """Test config is deep copied (independent instances)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config1 = load_config(str(Path(tmpdir) / "nonexistent.yaml"))
            config2 = load_config(str(Path(tmpdir) / "nonexistent.yaml"))
            
            # Modify config1
            config1["scanner"]["max_depth"] = 999
            
            # config2 should not be affected
            assert config2["scanner"]["max_depth"] == 3

    def test_numeric_types_preserved(self):
        """Test numeric types are preserved"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "types.yaml"
            config_file.write_text("""
scanner:
  max_depth: 10
  timeout: 15
  rate_limit: 8.5
""")
            
            config = load_config(str(config_file))
            
            assert isinstance(config["scanner"]["max_depth"], int)
            assert isinstance(config["scanner"]["timeout"], int)
            assert isinstance(config["scanner"]["rate_limit"], float)

    def test_boolean_types_preserved(self):
        """Test boolean types are preserved"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "bools.yaml"
            config_file.write_text("""
modules:
  sqli: true
  xss: false
scanner:
  verify_ssl: false
""")
            
            config = load_config(str(config_file))
            
            assert config["modules"]["sqli"] is True
            assert config["modules"]["xss"] is False
            assert config["scanner"]["verify_ssl"] is False
