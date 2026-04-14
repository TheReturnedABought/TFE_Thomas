"""
tests/unit/test_image_analyzer.py

Unit tests for analyzers/image_analyzer.py — DockerImageAnalyzer.

Covers:
    - extract_metadata() — returns expected keys (size, layers, base_image, labels, env_vars)
    - detect_bad_practices() — root user inside image config
    - detect_bad_practices() — unversioned base image tag
    - detect_bad_practices() — excessive number of layers
    - detect_bad_practices() — sensitive environment variables in image config
    - detect_bad_practices() — missing labels
    - Clean image producing zero issues
    - Docker SDK unavailability handling
"""

import warnings
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_docker_image(metadata: dict) -> MagicMock:
    """Build a MagicMock that mimics the docker SDK Image object."""
    mock_image = MagicMock()
    mock_image.id = metadata["id"]
    mock_image.tags = metadata["tags"]
    mock_image.attrs = {
        "Size": int(metadata["size_mb"] * 1024 * 1024),
        "RootFS": {
            "Layers": ["sha256:layer" + str(i) for i in range(metadata["num_layers"])]
        },
        "Config": {
            "Image": metadata["base_image"],
            "Labels": metadata["labels"],
            "Env": metadata["env_vars"],
            "User": metadata.get("user", ""),
        },
        "Os": metadata["os"],
        "Architecture": metadata["architecture"],
    }
    return mock_image


def make_image_analyzer(metadata: dict):
    """Instantiate DockerImageAnalyzer with a fully mocked Docker client."""
    from analyzers.image_analyzer import DockerImageAnalyzer

    mock_client = MagicMock()
    mock_client.images.get.return_value = _make_mock_docker_image(metadata)
    with patch("analyzers.image_analyzer.docker.from_env", return_value=mock_client):
        analyzer = DockerImageAnalyzer(
            metadata["tags"][0] if metadata["tags"] else metadata["id"]
        )
    return analyzer


# ---------------------------------------------------------------------------
# extract_metadata
# ---------------------------------------------------------------------------


class TestExtractMetadata:

    def test_returns_dict(self, mock_image_metadata):
        """Test returns dict."""
        analyzer = make_image_analyzer(mock_image_metadata)
        result = analyzer.extract_metadata()
        assert isinstance(result, dict)

    def test_contains_required_keys(self, mock_image_metadata):
        """Test contains required keys."""
        analyzer = make_image_analyzer(mock_image_metadata)
        result = analyzer.extract_metadata()
        required_keys = {"size_mb", "num_layers", "base_image", "labels", "env_vars"}
        assert required_keys.issubset(
            result.keys()
        ), f"Missing keys: {required_keys - result.keys()}"

    def test_size_is_positive_number(self, mock_image_metadata):
        """Test size is positive number."""
        analyzer = make_image_analyzer(mock_image_metadata)
        result = analyzer.extract_metadata()
        assert isinstance(result["size_mb"], (int, float))
        assert result["size_mb"] > 0

    def test_num_layers_matches_expected(self, mock_image_metadata):
        """Test num layers matches expected."""
        analyzer = make_image_analyzer(mock_image_metadata)
        result = analyzer.extract_metadata()
        assert result["num_layers"] == mock_image_metadata["num_layers"]

    def test_base_image_extracted_correctly(self, mock_image_metadata):
        """Test base image extracted correctly."""
        analyzer = make_image_analyzer(mock_image_metadata)
        result = analyzer.extract_metadata()
        assert result["base_image"] == mock_image_metadata["base_image"]

    def test_labels_returned_as_dict(self, mock_image_metadata):
        """Test labels returned as dict."""
        analyzer = make_image_analyzer(mock_image_metadata)
        result = analyzer.extract_metadata()
        assert isinstance(result["labels"], dict)

    def test_env_vars_returned_as_list(self, mock_image_metadata):
        """Test env vars returned as list."""
        analyzer = make_image_analyzer(mock_image_metadata)
        result = analyzer.extract_metadata()
        assert isinstance(result["env_vars"], list)

    def test_image_not_found_raises_error(self):
        """Test image not found raises error."""
        import docker

        from analyzers.image_analyzer import DockerImageAnalyzer

        mock_client = MagicMock()
        mock_client.images.get.side_effect = docker.errors.ImageNotFound("not_found")
        with patch(
            "analyzers.image_analyzer.docker.from_env", return_value=mock_client
        ):
            with pytest.raises(docker.errors.ImageNotFound):
                DockerImageAnalyzer("nonexistent:image")


# ---------------------------------------------------------------------------
# detect_bad_practices — root user
# ---------------------------------------------------------------------------


class TestRootUserDetection:

    def test_root_user_in_config_raises_issue(self, mock_image_metadata):
        """Test root user in config raises issue."""
        metadata = {**mock_image_metadata, "user": "root"}
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        assert any(
            "root" in i.description.lower() or "user" in i.id.lower() for i in issues
        ), "Expected a root user issue"

    def test_empty_user_treated_as_root(self, mock_image_metadata):
        """Test empty user treated as root."""
        metadata = {**mock_image_metadata, "user": ""}
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        assert any(
            "root" in i.description.lower() or "user" in i.description.lower()
            for i in issues
        )

    def test_non_root_user_no_issue(self, mock_image_metadata):
        """Test non root user no issue."""
        metadata = {**mock_image_metadata, "user": "appuser"}
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        root_issues = [i for i in issues if "root" in i.description.lower()]
        assert len(root_issues) == 0


# ---------------------------------------------------------------------------
# detect_bad_practices — unversioned base image
# ---------------------------------------------------------------------------


class TestBaseImageVersioningImage:

    def test_latest_base_image_raises_issue(self, mock_image_metadata_bad):
        """Test latest base image raises issue."""
        # mock_image_metadata_bad has base_image: ubuntu:latest
        analyzer = make_image_analyzer(mock_image_metadata_bad)
        issues = analyzer.detect_bad_practices()
        assert any(
            "latest" in i.description.lower() or "version" in i.description.lower()
            for i in issues
        )

    def test_pinned_base_image_no_issue(self, mock_image_metadata):
        """Test pinned base image no issue."""
        # mock_image_metadata has base_image: python:3.11-slim
        metadata = {**mock_image_metadata, "user": "appuser"}
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        version_issues = [i for i in issues if "latest" in i.description.lower()]
        assert len(version_issues) == 0


# ---------------------------------------------------------------------------
# detect_bad_practices — excessive layers
# ---------------------------------------------------------------------------


class TestExcessiveLayers:

    def test_too_many_layers_raises_issue(self, mock_image_metadata):
        """Test too many layers raises issue."""
        metadata = {
            **mock_image_metadata,
            "num_layers": 50,
            "user": "appuser",
            "tags": ["myapp:1.0"],
            "base_image": "python:3.11-slim",
        }
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        assert any(
            "layer" in i.description.lower() for i in issues
        ), "Expected an issue for excessive number of layers"

    def test_normal_layer_count_no_issue(self, mock_image_metadata):
        """Test normal layer count no issue."""
        metadata = {**mock_image_metadata, "user": "appuser"}
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        layer_issues = [i for i in issues if "layer" in i.description.lower()]
        assert len(layer_issues) == 0


# ---------------------------------------------------------------------------
# detect_bad_practices — sensitive env vars
# ---------------------------------------------------------------------------


class TestSensitiveEnvVarsImage:

    def test_hardcoded_secret_in_env_raises_issue(self, mock_image_metadata_bad):
        """Test hardcoded secret in env raises issue."""
        # mock_image_metadata_bad has SECRET_KEY and DB_PASSWORD
        analyzer = make_image_analyzer(mock_image_metadata_bad)
        issues = analyzer.detect_bad_practices()
        assert any(
            "secret" in i.description.lower()
            or "password" in i.description.lower()
            or "env" in i.description.lower()
            for i in issues
        )

    def test_safe_env_vars_no_issue(self, mock_image_metadata):
        """Test safe env vars no issue."""
        # mock_image_metadata has PATH and PYTHONDONTWRITEBYTECODE
        metadata = {**mock_image_metadata, "user": "appuser"}
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        secret_issues = [
            i
            for i in issues
            if "secret" in i.description.lower() or "password" in i.description.lower()
        ]
        assert len(secret_issues) == 0


# ---------------------------------------------------------------------------
# detect_bad_practices — missing labels
# ---------------------------------------------------------------------------


class TestMissingLabels:

    def test_empty_labels_raises_issue(self, mock_image_metadata):
        """Test empty labels raises issue."""
        metadata = {**mock_image_metadata, "labels": {}, "user": "appuser"}
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        assert any(
            "label" in i.description.lower() for i in issues
        ), "Expected an issue for missing labels"

    def test_labels_present_no_issue(self, mock_image_metadata):
        """Test labels present no issue."""
        metadata = {
            **mock_image_metadata,
            "labels": {"maintainer": "dev@example.com", "version": "1.0"},
            "user": "appuser",
        }
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        label_issues = [i for i in issues if "label" in i.description.lower()]
        assert len(label_issues) == 0


# ---------------------------------------------------------------------------
# Clean image — zero issues
# ---------------------------------------------------------------------------


class TestCleanImage:

    def test_clean_image_returns_no_issues(self, mock_image_metadata):
        """Test clean image returns no issues."""
        metadata = {
            **mock_image_metadata,
            "user": "appuser",
            "labels": {"maintainer": "dev@example.com"},
        }
        analyzer = make_image_analyzer(metadata)
        issues = analyzer.detect_bad_practices()
        assert len(issues) == 0

    def test_issues_have_valid_severity(self, mock_image_metadata_bad):
        """Test issues have valid severity."""
        analyzer = make_image_analyzer(mock_image_metadata_bad)
        issues = analyzer.detect_bad_practices()
        valid = {"low", "medium", "critical"}
        for issue in issues:
            assert issue.severity in valid

    def test_issues_have_non_empty_recommendation(self, mock_image_metadata_bad):
        """Test issues have non empty recommendation."""
        analyzer = make_image_analyzer(mock_image_metadata_bad)
        issues = analyzer.detect_bad_practices()
        for issue in issues:
            assert (
                issue.recommendation
            ), "Each issue must include a non-empty recommendation"


# ---------------------------------------------------------------------------
# Docker daemon unavailable
# ---------------------------------------------------------------------------


class TestDockerDaemonUnavailable:

    def test_docker_not_running_raises_connection_error(self):
        """Test docker not running raises connection error."""
        import docker

        from analyzers.image_analyzer import DockerImageAnalyzer

        with patch(
            "analyzers.image_analyzer.docker.from_env",
            side_effect=docker.errors.DockerException(
                "Cannot connect to Docker daemon"
            ),
        ):
            with pytest.raises(docker.errors.DockerException):
                DockerImageAnalyzer("myapp:1.0")


# ---------------------------------------------------------------------------
# E2E test with real Docker daemon
# ---------------------------------------------------------------------------


class TestImageAnalyzerE2E:

    def test_alpine_image_real_analysis(self):
        """Test alpine image real analysis."""
        import docker

        try:
            client = docker.from_env()
            client.ping()
        except Exception as e:
            warnings.warn(f"Docker daemon is not available for real E2E tests: {e}")
            pytest.skip("Docker daemon not available")

        image_name = "alpine:latest"
        try:
            client.images.get(image_name)
        except docker.errors.ImageNotFound:
            try:
                client.images.pull(image_name)
            except Exception as e:
                warnings.warn(f"Failed to pull {image_name} for E2E testing: {e}")
                pytest.skip("Could not pull image for E2E test")

        from analyzers.image_analyzer import DockerImageAnalyzer

        analyzer = DockerImageAnalyzer(image_name)
        metadata = analyzer.extract_metadata()

        assert metadata["size_mb"] > 0
        assert metadata["num_layers"] > 0

        issues = analyzer.detect_bad_practices()

        # Alpine triggers "root user" warning since it has no explicit non-root user
        assert any(
            "root" in i.description.lower() or "user" in i.description.lower()
            for i in issues
        )
        # Alpine:latest also triggers unversioned base image
        assert any("latest" in i.description.lower() for i in issues)
