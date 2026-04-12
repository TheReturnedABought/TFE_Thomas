"""
utils/docker_client.py — Docker SDK wrapper (read-only).

Provides a thin wrapper around the Docker Python SDK to isolate all
Docker daemon communication in a single module.  All operations are
strictly read-only — no containers are started, stopped, or modified.
"""

from __future__ import annotations

from typing import Optional

try:
    import docker
    from docker.models.images import Image
    _DOCKER_AVAILABLE = True
except ImportError:
    _DOCKER_AVAILABLE = False


class DockerClient:
    """
    Read-only Docker client wrapper.

    Usage::

        client = DockerClient()
        if client.is_available():
            image = client.get_image("nginx:1.25")
    """

    def __init__(self) -> None:
        self._client = None
        if _DOCKER_AVAILABLE:
            self._client = docker.from_env()

    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the Docker daemon is reachable."""
        if self._client is None:
            return False
        try:
            self._client.ping()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------

    def get_image(self, name: str):
        """
        Retrieve a local Docker image by name or ID.

        Args:
            name: Image name, tag, or ID (e.g. ``nginx:1.25``).

        Returns:
            docker.models.images.Image

        Raises:
            docker.errors.ImageNotFound: if the image does not exist locally.
            docker.errors.DockerException: if the daemon is not reachable.
        """
        if self._client is None:
            raise RuntimeError("Docker SDK is not installed or Docker daemon is unavailable.")
        return self._client.images.get(name)

    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the underlying Docker client connection."""
        if self._client is not None:
            self._client.close()
