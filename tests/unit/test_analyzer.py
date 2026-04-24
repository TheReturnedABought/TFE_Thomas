from unittest.mock import MagicMock, patch

from core.analyzer import Analyzer
from core.config import Config


class Test_Analyzer___init__:
    def test_init(self):
        """Test init."""
        config = Config({"command": "all"})
        analyzer = Analyzer(config)
        assert analyzer._config == config


class Test_Analyzer_aggregate_results:
    @patch("analyzers.dockerfile_analyzer.DockerfileAnalyzer.detect_bad_practices")
    @patch("analyzers.dockerfile_analyzer.DockerfileAnalyzer.__init__")
    def test_aggregate_calls_correct_sub_analyzer(self, mock_init, mock_detect):
        """Test aggregate calls correct sub analyzer."""
        mock_init.return_value = None
        mock_detect.return_value = []
        config = Config({"command": "dockerfile", "dockerfile_path": "DF"})
        analyzer = Analyzer(config)
        # Mock _validate_path to avoid IO
        analyzer._validate_path = MagicMock(return_value=None)

        analyzer.aggregate_results()
        mock_detect.assert_called_once()


class Test_Analyzer__validate_path:
    def test_invalid_path_returns_issue(self):
        """Test invalid path returns issue."""
        config = Config({"command": "all"})
        analyzer = Analyzer(config)
        # Should catch non-existent path (SYS-002)
        issue = analyzer._validate_path("/non/existent/path", "test")
        assert issue is not None
        assert "SYS-002" in issue.id


class Test_Analyzer__run_dockerfile:
    """Tests for _run_dockerfile ensuring isolated error handling."""

    def test_run_dockerfile_success(self, tmp_path):
        """Test run dockerfile success."""
        f = tmp_path / "DF"
        # Use a more complete Dockerfile to minimize default issues
        f.write_text("FROM alpine:3.18\nHEALTHCHECK NONE\nUSER 1000\nWORKDIR /app\nEXPOSE 8080")
        config = Config({"command": "dockerfile", "dockerfile_path": str(f)})
        analyzer = Analyzer(config)
        result = analyzer._run_dockerfile()
        assert len(result.issues) == 0

    @patch("analyzers.dockerfile_analyzer.DockerfileAnalyzer.__init__")
    def test_run_dockerfile_crash_handled(self, mock_init, tmp_path):
        """Test run dockerfile crash handled."""
        f = tmp_path / "DF"
        f.write_text("FROM alpine")
        mock_init.side_effect = Exception("Crash")
        config = Config({"command": "dockerfile", "dockerfile_path": str(f)})
        analyzer = Analyzer(config)
        result = analyzer._run_dockerfile()
        assert any(i.id == "RUNTIME-ERROR" for i in result.issues)


class Test_Analyzer__run_compose:
    def test_run_compose_success(self, tmp_path):
        """Test run compose success."""
        f = tmp_path / "compose.yml"
        f.write_text("services:\n  web:\n    image: nginx:1.25")
        config = Config({"command": "compose", "compose_path": str(f)})
        analyzer = Analyzer(config)
        result = analyzer._run_compose()
        assert result is not None

    @patch("analyzers.compose_analyzer.ComposeAnalyzer.__init__")
    def test_run_compose_crash_handled(self, mock_init, tmp_path):
        """Test run compose crash handled."""
        f = tmp_path / "compose.yml"
        f.write_text("services: {}")
        mock_init.side_effect = Exception("Crash")
        config = Config({"command": "compose", "compose_path": str(f)})
        analyzer = Analyzer(config)
        result = analyzer._run_compose()
        assert any(i.id == "RUNTIME-ERROR" for i in result.issues)


class Test_Analyzer__run_swarm:
    def test_run_swarm_success(self, tmp_path):
        """Test run swarm success."""
        f = tmp_path / "stack.yml"
        f.write_text("services:\n  web:\n    image: nginx:1.25")
        config = Config({"command": "swarm", "swarm_path": str(f)})
        analyzer = Analyzer(config)
        result = analyzer._run_swarm()
        assert result is not None

    @patch("analyzers.swarm_analyzer.SwarmAnalyzer.__init__")
    def test_run_swarm_crash_handled(self, mock_init, tmp_path):
        """Test run swarm crash handled."""
        f = tmp_path / "stack.yml"
        f.write_text("services: {}")
        mock_init.side_effect = Exception("Crash")
        config = Config({"command": "swarm", "swarm_path": str(f)})
        analyzer = Analyzer(config)
        result = analyzer._run_swarm()
        assert any(i.id == "RUNTIME-ERROR" for i in result.issues)


class Test_Analyzer__run_image:
    @patch("analyzers.image_analyzer.DockerImageAnalyzer.__init__")
    def test_run_image_crash_handled(self, mock_init):
        """Test run image crash handled."""
        mock_init.side_effect = Exception("Docker unavailable")
        config = Config({"command": "image", "image_name": "alpine"})
        analyzer = Analyzer(config)
        result = analyzer._run_image()
        assert any(i.id == "IMAGE-ERROR" for i in result.issues)
