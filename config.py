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

    SEVERITY_ORDER = {"low": 0, "medium": 1, "critical": 2}

    def __init__(self, options: Dict[str, Any]) -> None:
        self._options = options

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_cli(cls, args) -> Config:
        """Build a Config from parsed argparse Namespace."""
        options: Dict[str, Any] = {
            "command":          getattr(args, "command", None),
            "output":           getattr(args, "output", "dockcheck_report.html"),
            "severity":         getattr(args, "severity", "low"),
            "no_report":        getattr(args, "no_report", False),
            "rules":            getattr(args, "rules", None),
            # Per-command targets
            "image_name":       (
                getattr(args, "image_name", None)   # "image" subcommand
                or getattr(args, "image", None)     # "all" subcommand
            ),
            "dockerfile_path":  (
                getattr(args, "dockerfile_path", None)
                or getattr(args, "dockerfile", None)
            ),
            "compose_path":     (
                getattr(args, "compose_path", None)
                or getattr(args, "compose", None)
            ),
        }
        return cls(options)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_option(self, key: str, default: Any = None) -> Any:
        """Return the value for *key*, or *default* if not found."""
        return self._options.get(key, default)

    def severity_passes(self, severity: str) -> bool:
        """
        Return True if *severity* meets or exceeds the configured threshold.

        Example: threshold="medium" → low=False, medium=True, critical=True
        """
        threshold = self._options.get("severity", "low")
        return (
            self.SEVERITY_ORDER.get(severity, 0)
            >= self.SEVERITY_ORDER.get(threshold, 0)
        )

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def command(self) -> Optional[str]:
        return self._options.get("command")

    @property
    def output_path(self) -> str:
        return self._options.get("output", "dockcheck_report.html")

    @property
    def rules_path(self) -> Optional[str]:
        return self._options.get("rules")

    def __repr__(self) -> str:  # pragma: no cover
        return f"Config({self._options!r})"
