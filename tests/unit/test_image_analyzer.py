from unittest.mock import MagicMock, patch

import docker.errors
import pytest

from analyzers.image_analyzer import DockerImageAnalyzer


class Test_DockerImageAnalyzer___init__:
    @patch("docker.from_env")
    def test_init_success(self, mock_env):
        """Test init success."""
        mock_image = MagicMock()
        mock_env.return_value.images.get.return_value = mock_image
        analyzer = DockerImageAnalyzer("alpine")
        assert analyzer._image_name == "alpine"
        assert analyzer._image == mock_image


class Test_DockerImageAnalyzer_extract_metadata:
    @patch("docker.from_env")
    def test_extract(self, mock_env):
        """Test extract."""
        mock_image = MagicMock()
        mock_image.attrs = {
            "Config": {"User": "root", "Env": ["PATH=/usr/bin"]},
            "RootFS": {"Layers": []},
            "Size": 1024,
        }
        mock_env.return_value.images.get.return_value = mock_image

        analyzer = DockerImageAnalyzer("alpine")
        meta = analyzer.extract_metadata()
        assert meta["user"] == "root"


class Test_DockerImageAnalyzer__build_context:
    @patch("docker.from_env")
    def test_build(self, mock_env):
        """Test build."""
        mock_env.return_value.images.get.return_value = MagicMock()
        analyzer = DockerImageAnalyzer("alpine")
        metadata = {
            "user": "0",
            "env_vars": ["FOO=BAR"],
            "labels": {"ver": "1.0"},
            "num_layers": 2,
        }
        ctx = analyzer._build_context(metadata)
        assert ctx["user"] == "0"
        assert ctx["num_layers"] == 2


class Test_DockerImageAnalyzer_detect_bad_practices:
    @patch("docker.from_env")
    def test_detection(self, mock_env):
        """Test detection."""
        mock_image = MagicMock()
        mock_image.attrs = {
            "Config": {"User": "root", "Env": ["S=1"]},
            "RootFS": {"Layers": []},
        }
        mock_env.return_value.images.get.return_value = mock_image

        analyzer = DockerImageAnalyzer("alpine")
        issues = analyzer.detect_bad_practices()
        assert any("IMG-004" in i.id or "image_running_as_root" in i.id for i in issues)
