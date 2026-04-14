from unittest.mock import MagicMock, patch

import pytest

from cli.cli import CLI
from models.analysis_result import AnalysisResult


@pytest.fixture
def mock_analyzer():
    with patch("cli.cli.Analyzer") as mock:
        yield mock


@pytest.fixture
def mock_report_generator():
    with patch("cli.cli.ReportGenerator") as mock:
        yield mock


@pytest.fixture
def mock_sarif_generator():
    with patch("cli.cli.SarifGenerator") as mock:
        yield mock


@pytest.fixture
def mock_fixer():
    with patch("cli.cli.YamlFixer") as mock_yaml, patch(
        "cli.cli.DockerfileFixer"
    ) as mock_docker:
        yield mock_yaml, mock_docker


def test_cli_dockerfile(mock_analyzer, mock_report_generator):
    """Test cli dockerfile."""
    with patch("sys.argv", ["dockcheck", "dockerfile", "Dockerfile"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value
        result = AnalysisResult()
        mock_instance.aggregate_results.return_value = result
        exit_code = cli.run()
        assert exit_code == 0
        mock_report_generator.assert_called_once()


def test_cli_compose(mock_analyzer, mock_report_generator):
    """Test cli compose."""
    with patch("sys.argv", ["dockcheck", "compose", "docker-compose.yml"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value
        mock_instance.aggregate_results.return_value = AnalysisResult()
        exit_code = cli.run()
        assert exit_code == 0


def test_cli_swarm(mock_analyzer, mock_report_generator):
    """Test cli swarm."""
    with patch("sys.argv", ["dockcheck", "swarm", "docker-compose.yml"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value
        mock_instance.aggregate_results.return_value = AnalysisResult()
        exit_code = cli.run()
        assert exit_code == 0


def test_cli_image(mock_analyzer, mock_report_generator):
    """Test cli image."""
    with patch("sys.argv", ["dockcheck", "image", "nginx"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value
        mock_instance.aggregate_results.return_value = AnalysisResult()
        exit_code = cli.run()
        assert exit_code == 0


def test_cli_all(mock_analyzer, mock_report_generator):
    """Test cli all."""
    with patch(
        "sys.argv",
        [
            "dockcheck",
            "all",
            "--image",
            "nginx",
            "--dockerfile",
            "Dockerfile",
            "--compose",
            "docker-compose.yml",
            "--swarm",
            "stack.yml",
        ],
    ):
        cli = CLI()
        mock_instance = mock_analyzer.return_value
        mock_instance.aggregate_results.return_value = AnalysisResult()
        exit_code = cli.run()
        assert exit_code == 0


def test_cli_no_report(mock_analyzer, mock_report_generator):
    """Test cli no report."""
    with patch("sys.argv", ["dockcheck", "--no-report", "dockerfile", "Dockerfile"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value
        mock_instance.aggregate_results.return_value = AnalysisResult()
        exit_code = cli.run()
        assert exit_code == 0
        mock_report_generator.assert_not_called()


def test_cli_sarif_output(mock_analyzer, mock_sarif_generator, mock_report_generator):
    """Test cli sarif output."""
    with patch(
        "sys.argv",
        ["dockcheck", "--sarif-output", "out.sarif", "dockerfile", "Dockerfile"],
    ):
        cli = CLI()
        mock_instance = mock_analyzer.return_value
        mock_instance.aggregate_results.return_value = AnalysisResult()
        exit_code = cli.run()
        assert exit_code == 0
        mock_sarif_generator.assert_called_once()
        mock_sarif_generator.return_value.generate.assert_called_once()


def test_cli_fix_flag(mock_analyzer, mock_fixer, mock_report_generator):
    """Test cli fix flag."""
    mock_yaml, mock_docker = mock_fixer
    with patch("sys.argv", ["dockcheck", "--fix", "dockerfile", "Dockerfile"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value

        from models.issue import Issue

        result = AnalysisResult()
        result.add_issue(
            Issue(
                id="DF-001",
                component="dockerfile",
                description="X",
                severity="medium",
                recommendation="Y",
            )
        )
        mock_instance.aggregate_results.return_value = result

        mock_docker.apply_fixes.return_value = 1

        exit_code = cli.run()
        assert exit_code == 1
        mock_docker.apply_fixes.assert_called_once()


def test_cli_fix_flag_compose(mock_analyzer, mock_fixer, mock_report_generator):
    """Test cli fix flag compose."""
    mock_yaml, mock_docker = mock_fixer
    with patch("sys.argv", ["dockcheck", "--fix", "compose", "docker-compose.yml"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value

        from models.issue import Issue

        result = AnalysisResult()
        result.add_issue(
            Issue(
                id="DC-001",
                component="compose",
                description="X",
                severity="low",
                recommendation="Y",
            )
        )

        # Test the all flag directly with fixes to cover all branches in one go
        with patch(
            "sys.argv",
            [
                "dockcheck",
                "--fix",
                "all",
                "--compose",
                "docker-compose.yml",
                "--dockerfile",
                "Dockerfile",
                "--swarm",
                "stack.yml",
            ],
        ):
            cli = CLI()
            mock_instance.aggregate_results.return_value = result

            mock_docker.apply_fixes.return_value = 1
            mock_yaml.apply_fixes.return_value = 2

            exit_code = cli.run()
            assert exit_code == 1
            mock_docker.apply_fixes.assert_called_once()
            assert mock_yaml.apply_fixes.call_count == 2


def test_cli_issues_found_exit_code(mock_analyzer, mock_report_generator):
    """Test cli issues found exit code."""
    with patch("sys.argv", ["dockcheck", "dockerfile", "Dockerfile"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value

        from models.issue import Issue

        result = AnalysisResult()
        result.metadata = {"test_meta": "value"}
        result.add_issue(
            Issue(
                id="DF-001",
                component="dockerfile",
                description="X",
                severity="critical",
                recommendation="Y",
            )
        )
        mock_instance.aggregate_results.return_value = result

        exit_code = cli.run()
        assert exit_code == 1


def test_cli_generic_exception(mock_analyzer):
    """Test cli generic exception."""
    with patch("sys.argv", ["dockcheck", "dockerfile", "Dockerfile"]):
        cli = CLI()
        mock_instance = mock_analyzer.return_value
        mock_instance.aggregate_results.side_effect = Exception("Generic Error Test")

        with pytest.raises(Exception):
            cli.run()
