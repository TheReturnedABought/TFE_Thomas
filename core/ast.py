"""
AST (Abstract Syntax Tree) classes for parsed artifacts.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class DockerNode:
    """Base class for all Dockerfile AST nodes."""

    instruction: str
    raw_value: str
    line_number: int


@dataclass(frozen=True)
class FromNode(DockerNode):
    """Represents a FROM instruction."""

    image: str
    tag: Optional[str] = None
    alias: Optional[str] = None


@dataclass(frozen=True)
class RunNode(DockerNode):
    """Represents a RUN instruction, combining multi-line fragments."""

    commands: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class EnvNode(DockerNode):
    """Represents an ENV instruction."""

    key: str
    value: str


@dataclass(frozen=True)
class CopyNode(DockerNode):
    """Represents a COPY instruction."""

    src: List[str] = field(default_factory=list)
    dst: str = ""


@dataclass(frozen=True)
class AddNode(DockerNode):
    """Represents an ADD instruction."""

    src: List[str] = field(default_factory=list)
    dst: str = ""


@dataclass(frozen=True)
class UserNode(DockerNode):
    """Represents a USER instruction."""

    user: str


@dataclass(frozen=True)
class WorkdirNode(DockerNode):
    """Represents a WORKDIR instruction."""

    path: str


@dataclass(frozen=True)
class LabelNode(DockerNode):
    """Represents a LABEL instruction."""

    labels: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class HealthcheckNode(DockerNode):
    """Represents a HEALTHCHECK instruction."""

    flags: List[str] = field(default_factory=list)
    command: str = ""


@dataclass(frozen=True)
class GenericNode(DockerNode):
    """Fallback node for unsupported instructions (EXPOSE, CMD, ENTRYPOINT, etc)."""

    pass
