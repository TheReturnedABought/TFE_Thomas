from unittest.mock import MagicMock, patch

import docker.errors
import pytest
import requests.exceptions

from utils.docker_client import DockerClient


class Test_DockerClient___init__:
    @patch("docker.from_env")
    def test_init(self, mock_env):
        """Test init."""
        client = DockerClient()
        assert client._client is not None


class Test_DockerClient_is_available:
    @patch("docker.from_env")
    def test_available(self, mock_env):
        """Test available."""
        mock_env.return_value.ping.return_value = True
        client = DockerClient()
        assert client.is_available() is True

    @patch("docker.from_env")
    def test_connection_error(self, mock_env):
        """Test connection error."""
        mock_env.return_value.ping.side_effect = requests.exceptions.ConnectionError()
        client = DockerClient()
        assert client.is_available() is False


class Test_DockerClient_get_image:
    @patch("docker.from_env")
    def test_get_success(self, mock_env):
        """Test get success."""
        mock_img = MagicMock()
        mock_env.return_value.images.get.return_value = mock_img
        client = DockerClient()
        client.is_available()  # Initialize
        img = client.get_image("alpine")
        assert img == mock_img

    @patch("docker.from_env")
    def test_get_not_found(self, mock_env):
        """Test get not found."""
        mock_env.return_value.images.get.side_effect = docker.errors.ImageNotFound(
            "Fail"
        )
        client = DockerClient()
        client.is_available()
        with pytest.raises(docker.errors.ImageNotFound):
            client.get_image("missing")


class Test_DockerClient_close:
    @patch("docker.from_env")
    def test_close_delegates(self, mock_env):
        """Test close delegates."""
        client = DockerClient()
        client.close()
        mock_env.return_value.close.assert_called_once()

    @patch("docker.from_env")
    def test_close_none_client(self, mock_env):
        """Test close none client."""
        client = DockerClient()
        client._client = None
        client.close()  # Should not raise
