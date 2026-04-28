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
        
        # history analysis
        history = attrs.get("History", [])
        history_has_add = False
        history_sys_upgrade = False
        history_secrets = False
        history_missing_checksum = False
        empty_layers = False
        history_debug_tools = False
        history_shell = False
        history_pkg_mgr = False

        for h in history:
            cmd = h.get("CreatedBy", "").lower()
            empty = h.get("EmptyLayer", False)
            if empty:
                empty_layers = True
            if " add " in cmd:
                history_has_add = True
            if "apt-get upgrade" in cmd or "apk upgrade" in cmd or "yum upgrade" in cmd:
                history_sys_upgrade = True
            if any(s in cmd for s in ["password=", "secret=", "token=", "key="]):
                history_secrets = True
            if ("wget " in cmd or "curl " in cmd) and "sha256sum" not in cmd:
                history_missing_checksum = True
            if any(s in cmd for s in ["strace", "gdb", "curl ", "wget "]):
                history_debug_tools = True
            if any(s in cmd for s in ["bash", "sh ", "ash", "zsh"]):
                history_shell = True
            if any(s in cmd for s in ["apt ", "apt-get", "apk ", "yum ", "dnf "]):
                history_pkg_mgr = True

        
        labels = config.get("Labels", {}) or {}
        missing_oci = True
        if "org.opencontainers.image.authors" in labels:
            missing_oci = False
            
        has_sbom = "org.opencontainers.image.sbom" in labels or "io.anchore.sbom" in labels
        has_slsa = "org.opencontainers.image.provenance" in labels or "slsa.dev/provenance" in labels

            
        expose = config.get("ExposedPorts", {}) or {}
        expose_all = False
        for k in expose:
            if "0.0.0.0" in k:
                expose_all = True
                
        env_vars = config.get("Env", []) or []
        # crude proxy for full os base: if os is ubuntu/debian/centos and size > 200MB
        full_os_base = False
        if attrs.get("Os", "") == "linux" and size_bytes > 200 * 1024 * 1024:
            if "ubuntu" in str(config.get("Image", "")).lower() or "debian" in str(config.get("Image", "")).lower():
                full_os_base = True

        debug_env = False
        for e in env_vars:
            if "DEBUG=1" in e or "NODE_ENV=development" in e.lower() or "NODE_ENV=dev" in e.lower():
                debug_env = True
                
        user = str(config.get("User", ""))
        explicit_root = False
        if user.lower() in ["root", "0"]:
            explicit_root = True
            
        volumes = config.get("Volumes", {}) or {}
        permissive_vols = len(volumes) > 0 # basic check for now


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
            "has_exposed_ports": bool(config.get("ExposedPorts")),
            "is_scratch_root": not bool(config.get("Image", "")) and not bool(config.get("User")),
            "has_cmd_or_entrypoint": bool(config.get("Cmd")) or bool(config.get("Entrypoint")),
            "img_no_healthcheck": not bool(config.get("Healthcheck")),
            "img_no_trust": not bool(attrs.get("DockerVersion")), # rough proxy if we don't have trust data
            "img_history_has_add": history_has_add,
            "img_history_system_upgrade": history_sys_upgrade,
            "img_generic_architecture": attrs.get("Architecture", "") not in ["amd64", "arm64", "s390x", "ppc64le"],
            "img_history_secrets": history_secrets,
            "img_explicit_root_user": explicit_root,
            "img_huge_layers": False, # Requires deep dive into sizes, hard via simple attrs
            "img_missing_oci_labels": missing_oci,
            "img_expose_all_interfaces": expose_all,
            "img_missing_os": not bool(attrs.get("Os")),
            "img_debug_env_vars": debug_env,
            "img_missing_entrypoint_or_cmd": not bool(config.get("Cmd")) and not bool(config.get("Entrypoint")),
            "img_empty_layers": empty_layers,
            "img_permissive_volumes": permissive_vols,
            "img_history_missing_checksum": history_missing_checksum,
            "img_missing_sbom": not has_sbom,
            "img_missing_slsa": not has_slsa,
            "img_full_os_base": full_os_base,
            "img_debug_tools": history_debug_tools,
            "img_shell_in_prod": history_shell,
            "img_pkg_manager": history_pkg_mgr,

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
            "size_mb": metadata.get("size_mb", 0.0),
            "has_exposed_ports": metadata.get("has_exposed_ports", False),
            "is_scratch_root": metadata.get("is_scratch_root", False),
            "tags": metadata.get("tags", []),
            "has_cmd_or_entrypoint": metadata.get("has_cmd_or_entrypoint", False),
            "img_no_healthcheck": metadata.get("img_no_healthcheck", False),
            "img_no_trust": metadata.get("img_no_trust", False),
            "img_history_has_add": metadata.get("img_history_has_add", False),
            "img_history_system_upgrade": metadata.get("img_history_system_upgrade", False),
            "img_generic_architecture": metadata.get("img_generic_architecture", False),
            "img_history_secrets": metadata.get("img_history_secrets", False),
            "img_explicit_root_user": metadata.get("img_explicit_root_user", False),
            "img_huge_layers": metadata.get("img_huge_layers", False),
            "img_missing_oci_labels": metadata.get("img_missing_oci_labels", False),
            "img_expose_all_interfaces": metadata.get("img_expose_all_interfaces", False),
            "img_missing_os": metadata.get("img_missing_os", False),
            "img_debug_env_vars": metadata.get("img_debug_env_vars", False),
            "img_missing_entrypoint_or_cmd": metadata.get("img_missing_entrypoint_or_cmd", False),
            "img_empty_layers": metadata.get("img_empty_layers", False),
            "img_permissive_volumes": metadata.get("img_permissive_volumes", False),
            "img_history_missing_checksum": metadata.get("img_history_missing_checksum", False),
        }
