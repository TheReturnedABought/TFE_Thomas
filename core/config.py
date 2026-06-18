"""
core/config.py — Configuration container for DockCheck.

Populated from CLI arguments via Config.from_cli() and consumed by
Analyzer and ReportGenerator.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class Config:
    """
    Holds all runtime options for a DockCheck run.

    Options stored:
        command         : str  — "image" | "dockerfile" | "compose" | "all"
        output          : str  — path for the generated HTML report
        severity        : str  — minimum severity threshold ("low"|"medium"|"critical")
        no_report       : bool — skip HTML generation if True
        rules           : str|None — path to a custom rules JSON file
        image_name      : str|None — for "image" / "all" commands
        dockerfile_path : str|None — for "dockerfile" / "all" commands
        compose_path    : str|None — for "compose" / "all" commands
    """

    SEVERITY_ORDER = {"low": 0, "medium": 1, "high":1.5, "critical": 2}

    def __init__(self, options: Dict[str, Any]) -> None:
        """
        Initialize the runtime Configuration with a dictionary of option mappings.

        Args:
            options (Dict[str, Any]): Dictionary of runtime configuration variables.
        """
        if not isinstance(options, dict):
            options = {}
        self._options = options

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_cli(cls, args) -> Config:
        """
        Factory method to construct a Config instance from parsed CLI arguments.

        Sanitizes path attributes to ensure type consistency (str or None).

        Args:
            args (argparse.Namespace): The parsed CLI arguments namespace.

        Returns:
            Config: A populated Config instance.
        """

        def _get_str(obj, attr):
            val = getattr(obj, attr, None)
            return str(val) if val is not None else None

        options: Dict[str, Any] = {
            "command": _get_str(args, "command"),
            "output": getattr(args, "output", "dockcheck_report.html"),
            "severity": _get_str(args, "severity") or "low",
            "no_report": bool(getattr(args, "no_report", False)),
            "rules": _get_str(args, "rules"),
            "sarif_output": getattr(args, "sarif_output", None),
            # Per-command targets
            "image_name": (
                _get_str(args, "image_name")  # "image" subcommand
                or _get_str(args, "image")  # "all" subcommand
            ),
            "dockerfile_path": (
                _get_str(args, "dockerfile_path") or _get_str(args, "dockerfile")
            ),
            "compose_path": (
                _get_str(args, "compose_path") or _get_str(args, "compose")
            ),
            "swarm_path": (_get_str(args, "swarm_path") or _get_str(args, "swarm")),
        }
        return cls(options)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_option(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a configuration option by its key.

        Args:
            key (str): The configuration setting key to lookup.
            default (Any, optional): Fallback value if key is not set. Defaults to None.

        Returns:
            Any: The configured value or the specified default fallback.
        """
        if not isinstance(key, str):
            return default
        return self._options.get(key, default)

    def severity_passes(self, severity: str) -> bool:
        """
        Determine if a given severity level meets or exceeds the configured threshold.

        Used to dynamically filter reported analysis issues based on user-supplied thresholds.

        Args:
            severity (str): The severity level to test (e.g., 'low', 'medium', 'critical').

        Returns:
            bool: True if the severity passes the threshold filters, False otherwise.
        """
        if not isinstance(severity, str):
            return False
        threshold = self._options.get("severity", "low")
        return self.SEVERITY_ORDER.get(severity, 0) >= self.SEVERITY_ORDER.get(
            threshold, 0
        )

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def command(self) -> Optional[str]:
        """
        Get the parsed sub-analysis command to execute.

        Returns:
            Optional[str]: The command name or None.
        """
        return self._options.get("command")

    @property
    def output_path(self) -> str:
        """
        Get the target path for the generated HTML report file.

        Returns:
            str: Absolute or relative output path. Defaults to 'dockcheck_report.html'.
        """
        return self._options.get("output", "dockcheck_report.html")

    @property
    def rules_path(self) -> Optional[str]:
        """
        Get the custom rules JSON file path if specified.

        Returns:
            Optional[str]: The path to the custom rules file, or None if built-in rules are used.
        """
        return self._options.get("rules")

    def __repr__(self) -> str:  # pragma: no cover
        return f"Config({self._options!r})"
