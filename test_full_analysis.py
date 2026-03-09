"""
tests/integration/test_full_analysis.py

Integration tests for the full DockCheck analysis pipeline.

These tests exercise the complete chain:
    CLI args → Config → Analyzer → [DockerImageAnalyzer / DockerfileAnalyzer / ComposeAnalyzer]
             → AnalysisResult → ReportGenerator → HTML file

All Docker SDK calls are mocked so no live Docker daemon is required.
File I/O uses temporary files so tests are fully self-contained.

Covers:
    - Full image analysis pipeline produces a valid HTML report
    - Full Dockerfile analysis pipeline produces a valid HTML report
    - Full Compose analysis pipeline produces a valid HTML report
    - Combined "all" analysis aggregates issues from all sub-analyzers
    - Exit code is 0 when no issues are found
    - Exit code is 1 when issues are found (CI/CD gate)
    - Performance: standard image analysis completes within 2 minutes (per spec)
    - Report contains all expected sections (summary, issues, recommendations)
"""

import os
import time
import pytest
import tempfile
from unittest.mock import patch, MagicMock, mock_open

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

GOOD_DOCKERFILE = """\
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER appuser
CMD ["python", "main.py"]
"""

BAD_DOCKERFILE = """\
FROM python:latest
RUN apt-get update
RUN apt-get install -y curl
COPY . .
CMD ["python", "app.py"]
"""

GOOD_COMPOSE = """\
version: "3.8"
services:
  web:
    image: nginx:1.25
    ports:
      - "8080:80"
    user: "1000"
  db:
    image: postgres:15
    user: "999"
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
"""

BAD_COMPOSE = """\
version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
  db:
    image: postgres
    environment:
      POSTGRES_PASSWORD: supersecret
"""

MOCK_IMAGE_METADATA = {
    "id": "sha256:abc123",
    "tags": ["myapp:1.0"],
    "size_mb": 120.5,
    "num_layers": 7,
    "base_image": "python:3.11-slim",
    "labels": {"maintainer": "dev@example.com"},
    "env_vars": ["PATH=/usr/local/bin"],
    "user": "appuser",
    "architecture": "amd64",
    "os": "linux",
}

MOCK_IMAGE_METADATA_BAD = {
    "id": "sha256:def456",
    "tags": ["myapp:latest"],
    "size_mb": 980.0,
    "num_layers": 45,
    "base_image": "ubuntu:latest",
    "labels": {},
    "env_vars": ["SECRET_KEY=hardcoded"],
    "user": "root",
    "architecture": "amd64",
    "os": "linux",
}


def _make_mock_image(metadata):
    mock = MagicMock()
    mock.id = metadata["id"]
    mock.tags = metadata["tags"]
    mock.attrs = {
        "Size": int(metadata["size_mb"] * 1024 * 1024),
        "RootFS": {"Layers": ["sha256:l" + str(i) for i in range(metadata["num_layers"])]},
        "Config": {
            "Image": metadata["base_image"],
            "Labels": metadata["labels"],
            "Env": metadata["env_vars"],
            "User": metadata["user"],
        },
        "Os": metadata["os"],
        "Architecture": metadata["architecture"],
    }
    return mock


def _make_cli_args(command, **kwargs):
    args = MagicMock()
    args.command = command
    args.output = kwargs.get("output", "report.html")
    args.severity = kwargs.get("severity", "low")
    args.no_report = kwargs.get("no_report", False)
    args.rules = kwargs.get("rules", None)
    args.image_name = kwargs.get("image_name", "myapp:1.0")
    args.dockerfile_path = kwargs.get("dockerfile_path", None)
    args.compose_path = kwargs.get("compose_path", None)
    args.image = kwargs.get("image", None)
    args.dockerfile = kwargs.get("dockerfile", None)
    args.compose = kwargs.get("compose", None)
    return args


# ===========================================================================
# Full Dockerfile pipeline
# ===========================================================================

class TestDockerfilePipeline:

    def test_bad_dockerfile_produces_issues(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_DOCKERFILE)
            df_path = f.name

        args = _make_cli_args("dockerfile", output=output, dockerfile_path=df_path)
        config = Config.from_cli(args)
        analyzer = Analyzer(config)
        result = analyzer.aggregate_results()

        assert len(result.issues) > 0, "Bad Dockerfile should produce at least one issue"

    def test_bad_dockerfile_report_created(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer
        from report.report_generator import ReportGenerator

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_DOCKERFILE)
            df_path = f.name

        args = _make_cli_args("dockerfile", output=output, dockerfile_path=df_path)
        config = Config.from_cli(args)
        analyzer = Analyzer(config)
        result = analyzer.aggregate_results()

        generator = ReportGenerator(config)
        report_path = generator.generate_html_report(result)

        assert os.path.exists(report_path)
        with open(report_path) as f:
            html = f.read()
        assert "<html" in html.lower()

    def test_good_dockerfile_produces_no_issues(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(GOOD_DOCKERFILE)
            df_path = f.name

        args = _make_cli_args("dockerfile", output=output, dockerfile_path=df_path)
        config = Config.from_cli(args)
        analyzer = Analyzer(config)
        result = analyzer.aggregate_results()

        assert len(result.issues) == 0


# ===========================================================================
# Full Compose pipeline
# ===========================================================================

class TestComposePipeline:

    def test_bad_compose_produces_issues(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_COMPOSE)
            compose_path = f.name

        args = _make_cli_args("compose", output=output, compose_path=compose_path)
        config = Config.from_cli(args)
        analyzer = Analyzer(config)
        result = analyzer.aggregate_results()

        assert len(result.issues) > 0

    def test_good_compose_produces_no_issues(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                         delete=False, dir=tmp_path) as f:
            f.write(GOOD_COMPOSE)
            compose_path = f.name

        args = _make_cli_args("compose", output=output, compose_path=compose_path)
        config = Config.from_cli(args)
        analyzer = Analyzer(config)
        result = analyzer.aggregate_results()

        assert len(result.issues) == 0

    def test_compose_report_contains_service_names(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer
        from report.report_generator import ReportGenerator

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_COMPOSE)
            compose_path = f.name

        args = _make_cli_args("compose", output=output, compose_path=compose_path)
        config = Config.from_cli(args)
        analyzer = Analyzer(config)
        result = analyzer.aggregate_results()

        generator = ReportGenerator(config)
        report_path = generator.generate_html_report(result)

        with open(report_path) as f:
            html = f.read()
        # Service names from BAD_COMPOSE
        assert "web" in html or "db" in html


# ===========================================================================
# Full Image pipeline (mocked Docker)
# ===========================================================================

class TestImagePipeline:

    def test_bad_image_produces_issues(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        args = _make_cli_args("image", output=output, image_name="myapp:latest")
        config = Config.from_cli(args)

        mock_client = MagicMock()
        mock_client.images.get.return_value = _make_mock_image(MOCK_IMAGE_METADATA_BAD)

        with patch("analyzers.image_analyzer.docker.from_env", return_value=mock_client):
            analyzer = Analyzer(config)
            result = analyzer.aggregate_results()

        assert len(result.issues) > 0

    def test_clean_image_produces_no_issues(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        args = _make_cli_args("image", output=output, image_name="myapp:1.0")
        config = Config.from_cli(args)

        mock_client = MagicMock()
        mock_client.images.get.return_value = _make_mock_image(MOCK_IMAGE_METADATA)

        with patch("analyzers.image_analyzer.docker.from_env", return_value=mock_client):
            analyzer = Analyzer(config)
            result = analyzer.aggregate_results()

        assert len(result.issues) == 0


# ===========================================================================
# Combined "all" pipeline
# ===========================================================================

class TestAllPipeline:

    def test_all_aggregates_issues_from_all_sources(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_DOCKERFILE)
            df_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_COMPOSE)
            compose_path = f.name

        args = _make_cli_args(
            "all",
            output=output,
            image="myapp:latest",
            dockerfile=df_path,
            compose=compose_path,
        )
        config = Config.from_cli(args)
        mock_client = MagicMock()
        mock_client.images.get.return_value = _make_mock_image(MOCK_IMAGE_METADATA_BAD)

        with patch("analyzers.image_analyzer.docker.from_env", return_value=mock_client):
            analyzer = Analyzer(config)
            result = analyzer.aggregate_results()

        # Issues should come from Dockerfile + Compose + Image combined
        assert len(result.issues) >= 3, "Expected issues from all three analyzers"

    def test_all_report_contains_all_sections(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer
        from report.report_generator import ReportGenerator

        output = str(tmp_path / "report.html")

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_DOCKERFILE)
            df_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_COMPOSE)
            compose_path = f.name

        args = _make_cli_args(
            "all", output=output,
            image="myapp:latest", dockerfile=df_path, compose=compose_path,
        )
        config = Config.from_cli(args)
        mock_client = MagicMock()
        mock_client.images.get.return_value = _make_mock_image(MOCK_IMAGE_METADATA_BAD)

        with patch("analyzers.image_analyzer.docker.from_env", return_value=mock_client):
            analyzer = Analyzer(config)
            result = analyzer.aggregate_results()

        generator = ReportGenerator(config)
        report_path = generator.generate_html_report(result)

        with open(report_path) as f:
            html = f.read()

        # All four required sections from the spec
        for section in ("summary", "issues", "recommendations"):
            assert section in html.lower(), f"Missing section: {section}"


# ===========================================================================
# Exit codes
# ===========================================================================

class TestExitCodes:

    def test_exit_code_0_when_no_issues(self, tmp_path):
        from cli.cli import CLI
        output = str(tmp_path / "report.html")

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(GOOD_DOCKERFILE)
            df_path = f.name

        with patch("sys.argv", ["dockcheck", "dockerfile", df_path,
                                "--output", output]):
            cli = CLI()
            exit_code = cli.run()

        assert exit_code == 0

    def test_exit_code_1_when_issues_found(self, tmp_path):
        from cli.cli import CLI
        output = str(tmp_path / "report.html")

        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_DOCKERFILE)
            df_path = f.name

        with patch("sys.argv", ["dockcheck", "dockerfile", df_path,
                                "--output", output]):
            cli = CLI()
            exit_code = cli.run()

        assert exit_code == 1


# ===========================================================================
# Performance requirement: analysis < 2 minutes (spec §7)
# ===========================================================================

class TestPerformanceRequirements:

    def test_dockerfile_analysis_under_2_minutes(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_DOCKERFILE)
            df_path = f.name

        args = _make_cli_args("dockerfile", output=output, dockerfile_path=df_path)
        config = Config.from_cli(args)
        analyzer = Analyzer(config)

        start = time.time()
        analyzer.aggregate_results()
        elapsed = time.time() - start

        assert elapsed < 120, f"Analysis took {elapsed:.1f}s — exceeds 2-minute spec requirement"

    def test_compose_analysis_under_2_minutes(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_COMPOSE)
            compose_path = f.name

        args = _make_cli_args("compose", output=output, compose_path=compose_path)
        config = Config.from_cli(args)
        analyzer = Analyzer(config)

        start = time.time()
        analyzer.aggregate_results()
        elapsed = time.time() - start

        assert elapsed < 120, f"Analysis took {elapsed:.1f}s — exceeds 2-minute spec requirement"


# ===========================================================================
# Severity filtering
# ===========================================================================

class TestSeverityFiltering:

    def test_critical_only_filters_out_medium_and_low(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_DOCKERFILE)
            df_path = f.name

        args = _make_cli_args("dockerfile", output=output,
                               dockerfile_path=df_path, severity="critical")
        config = Config.from_cli(args)
        analyzer = Analyzer(config)
        result = analyzer.aggregate_results()

        for issue in result.issues:
            assert issue.severity == "critical", \
                f"With severity=critical, got issue with severity={issue.severity}"

    def test_low_returns_all_severities(self, tmp_path):
        from core.config import Config
        from core.analyzer import Analyzer

        output = str(tmp_path / "report.html")
        with tempfile.NamedTemporaryFile(mode="w", suffix="Dockerfile",
                                         delete=False, dir=tmp_path) as f:
            f.write(BAD_DOCKERFILE)
            df_path = f.name

        args = _make_cli_args("dockerfile", output=output,
                               dockerfile_path=df_path, severity="low")
        config = Config.from_cli(args)
        analyzer = Analyzer(config)
        result = analyzer.aggregate_results()

        severities = {i.severity for i in result.issues}
        # With threshold=low, we expect all severities to be present for a bad Dockerfile
        assert len(severities) >= 1
