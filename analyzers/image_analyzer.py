"""
analyzers/image_analyzer.py — Static analysis of Docker images.

Extracts metadata from a local Docker image via the Docker SDK and runs
all image-related rules from the RulesEngine against the extracted context.

Requires a running Docker daemon for metadata extraction (read-only).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import docker

from core.rules_engine import RulesEngine
from models.issue import Issue

# Default rules file relative to the project root
_DEFAULT_RULES = os.path.join(
    os.path.dirname(__file__), "..", "rules", "default_rules.json"
)


class DockerImageAnalyzer:
    """
    Analyses a local Docker image for bad practices and misconfigurations.

    Args:
        image_name: Name, tag, or ID of the local Docker image.
        rules_path: Optional path to a custom rules JSON file.
    """

    def __init__(self, image_name: str, rules_path: Optional[str] = None) -> None:
        self._image_name = image_name
        self._rules_path = rules_path or _DEFAULT_RULES
        self._engine = RulesEngine(self._rules_path)
        self._engine.load_rules()

        # Connect to Docker daemon and fetch the image object
        self._client = docker.from_env()
        self._image = self._client.images.get(image_name)

    # ------------------------------------------------------------------
    # Public: metadata extraction
    # ------------------------------------------------------------------

    def extract_metadata(self) -> Dict[str, Any]:
        """
        Extract metadata from the Docker image.

        Returns:
            dict with keys: size_mb, num_layers, base_image, labels,
            env_vars, user, tags, architecture, os.

        Raises:
            docker.errors.ImageNotFound: if the image is not available locally.
        """
        attrs = self._image.attrs
        config = attrs.get("Config", {})
        rootfs = attrs.get("RootFS", {})

        size_bytes = attrs.get("Size", 0)
        layers = rootfs.get("Layers", [])

        return {
            "size_mb": round(size_bytes / (1024 * 1024), 2),
            "num_layers": len(layers),
            "base_image": config.get("Image", ""),
            "labels": config.get("Labels", {}) or {},
            "env_vars": config.get("Env", []) or [],
            "user": config.get("User", ""),
            "tags": self._image.tags,
            "architecture": attrs.get("Architecture", ""),
            "os": attrs.get("Os", ""),
        }

    # ------------------------------------------------------------------
    # Public: analysis
    # ------------------------------------------------------------------

    def detect_bad_practices(self) -> List[Issue]:
        """
        Run all image rules and return a list of Issue objects.

        Returns:
            list of Issue objects (empty list if no problems found).
        """
        metadata = self.extract_metadata()
        context = self._build_context(metadata)
        return self._engine.evaluate_all(context, component_filter="image")

    # ------------------------------------------------------------------
    # Context builder
    # ------------------------------------------------------------------

    def _build_context(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Convert extracted metadata into a context dict for the RulesEngine."""
        return {
            "component": "image",
            "base_image": metadata.get("base_image", ""),
            "user": metadata.get("user", "") or "root",
            "labels": metadata.get("labels", {}),
            "env_vars": metadata.get("env_vars", []),
            "num_layers": metadata.get("num_layers", 0),
        }
