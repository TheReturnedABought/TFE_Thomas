"""
models/issue.py — Issue dataclass.

Represents a single problem detected during analysis, with a severity level,
a human-readable description, the component it belongs to, and a concrete
recommendation for fixing it.
"""

from dataclasses import dataclass
from typing import Set

VALID_SEVERITIES: Set[str] = {"low", "medium", "critical"}


@dataclass
class Issue:
    """A single analysis finding."""

    id: str
    description: str
    severity: str
    component: str
    recommendation: str

    def __post_init__(self) -> None:
        # Type coercion (discovered via Deep Chaos Monte Carlo)
        self.id = str(self.id) if self.id is not None else ""
        self.description = str(self.description) if self.description is not None else ""
        self.severity = str(self.severity) if self.severity is not None else ""
        self.component = str(self.component) if self.component is not None else ""
        self.recommendation = (
            str(self.recommendation) if self.recommendation is not None else ""
        )

        if not self.id or not self.id.strip():
            raise ValueError("Issue.id must not be empty.")
        if not self.description or not self.description.strip():
            raise ValueError("Issue.description must not be empty.")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}'. "
                f"Must be one of: {', '.join(sorted(VALID_SEVERITIES))}."
            )
        if not self.recommendation or not self.recommendation.strip():
            raise ValueError("Issue.recommendation must not be empty.")

    def __repr__(self) -> str:
        return (
            f"Issue(id={self.id!r}, severity={self.severity!r}, "
            f"component={self.component!r}, description={self.description!r})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Issue):
            return NotImplemented
        return (
            self.id == other.id
            and self.description == other.description
            and self.severity == other.severity
            and self.component == other.component
            and self.recommendation == other.recommendation
        )
