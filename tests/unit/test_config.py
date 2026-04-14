from unittest.mock import MagicMock

import pytest

from core.config import Config
from tests.utils.fuzz_data import get_hybrid_param, random_string


class Test_Config_from_cli:
    """Tests for the Config.from_cli factory method."""

    def test_basic_cli(self):
        """Test basic cli."""
        # 50% chance real data, 50% garbage
        cmd = get_hybrid_param("dockerfile", lambda: random_string(10))
        path = get_hybrid_param("Dockerfile", lambda: random_string(100))

        args = MagicMock()
        args.command = cmd
        args.dockerfile_path = path
        args.rules = None

        config = Config.from_cli(args)
        assert config.command == str(cmd)
        assert config.get_option("dockerfile_path") == str(path)


class Test_Config_get_option:
    """Tests for the get_option retrieval logic."""

    def test_get_existing(self):
        """Test get existing."""
        options = {"key": get_hybrid_param("value")}
        config = Config(options)
        assert config.get_option("key") == options["key"]

    def test_get_default(self):
        """Test get default."""
        config = Config({})
        default = get_hybrid_param("default_val")
        assert config.get_option("non_existent", default) == default


class Test_Config_severity_passes:
    """Tests for the severity threshold filtering."""

    @pytest.mark.parametrize(
        "threshold, check, expected",
        [
            ("low", "low", True),
            ("medium", "low", False),
            ("critical", "medium", False),
            ("critical", "critical", True),
        ],
    )
    def test_thresholds(self, threshold, check, expected):
        """Test thresholds."""
        # Hybrid: 50% regular, 50% random garbage severity
        if get_hybrid_param(True, lambda: False):
            # Deterministic test
            config = Config({"severity": threshold})
            assert config.severity_passes(check) == expected
        else:
            # Monte Carlo test (just ensure no crash)
            config = Config({"severity": random_string(5)})
            config.severity_passes(random_string(5))


class Test_Config_command:
    def test_command(self):
        """Test command."""
        config = Config({"command": "all"})
        assert config.command == "all"

    def test_command_none(self):
        """Test command none."""
        config = Config({})
        assert config.command is None


class Test_Config_output_path:
    def test_output_path_default(self):
        """Test output path default."""
        config = Config({})
        assert config.output_path == "dockcheck_report.html"

    def test_output_path_custom(self):
        """Test output path custom."""
        config = Config({"output": "my_report.html"})
        assert config.output_path == "my_report.html"


class Test_Config_rules_path:
    def test_rules_path(self):
        """Test rules path."""
        config = Config({"rules": "rules.json"})
        assert config.rules_path == "rules.json"

    def test_rules_path_none(self):
        """Test rules path none."""
        config = Config({})
        assert config.rules_path is None


class Test_Config_type_guards:
    """Tests for defensive type guards discovered via Deep Chaos Monte Carlo."""

    def test_non_dict_options_handled(self):
        """Test non dict options handled."""
        config = Config(None)
        assert config.get_option("key", "default") == "default"

    def test_get_option_non_str_key(self):
        """Test get option non str key."""
        config = Config({"a": 1})
        assert config.get_option(123, "fallback") == "fallback"

    def test_severity_passes_non_str(self):
        """Test severity passes non str."""
        config = Config({"severity": "low"})
        assert config.severity_passes(999) is False
