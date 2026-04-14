"""
A State-Machine Lexical Parser for Dockerfiles.
Converts raw Dockerfile text into an Abstract Syntax Tree (AST) of DockerNode objects.
Handles line continuations properly to defeat brittle Regex parsing.
"""

from typing import List

from core.ast import (
    AddNode,
    CopyNode,
    DockerNode,
    EnvNode,
    FromNode,
    GenericNode,
    HealthcheckNode,
    LabelNode,
    RunNode,
    UserNode,
    WorkdirNode,
)


class DockerfileParser:
    """
    Parses a string of Dockerfile text into a sequence of AST nodes.
    """

    def parse(self, content: str) -> List[DockerNode]:
        nodes: List[DockerNode] = []
        if not content:
            return nodes

        logical_lines = self._lex_lines(content)

        for line_num, line_content in logical_lines:
            node = self._parse_instruction(line_content, line_num)
            if node:
                nodes.append(node)

        return nodes

    def _lex_lines(self, content: str) -> List[tuple[int, str]]:
        """
        Lexes the raw text into logical lines, resolving line continuations (\\).
        Returns a list of tuples: (start_line_number, logical_content).
        """
        logical_lines = []
        current_logical_line = []
        start_line_num = 0
        in_continuation = False

        for i, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if not in_continuation:
                start_line_num = i

            if line.endswith("\\"):
                current_logical_line.append(line[:-1].rstrip())
                in_continuation = True
            else:
                current_logical_line.append(line)
                logical_lines.append(
                    (start_line_num, " ".join(current_logical_line).strip())
                )
                current_logical_line = []
                in_continuation = False

        # If file ends with a continuation
        if current_logical_line:
            logical_lines.append(
                (start_line_num, " ".join(current_logical_line).strip())
            )

        return logical_lines

    def _parse_instruction(self, logical_line: str, line_num: int) -> DockerNode:
        """Parses a single logical line into the correct DockerNode subclass."""
        parts = logical_line.split(None, 1)
        if not parts:
            return GenericNode(instruction="", raw_value="", line_number=line_num)

        command = parts[0].upper()
        value = parts[1] if len(parts) > 1 else ""

        if command == "FROM":
            v_parts = value.split()
            image = v_parts[0] if v_parts else ""
            tag = None
            if ":" in image:
                image, tag = image.split(":", 1)

            alias = None
            if len(v_parts) == 3 and v_parts[1].upper() == "AS":
                alias = v_parts[2]

            return FromNode(
                instruction=command,
                raw_value=value,
                line_number=line_num,
                image=image,
                tag=tag,
                alias=alias,
            )

        elif command == "RUN":
            # For simplicity, we just split on && for distinct commands
            commands = [cmd.strip() for cmd in value.split("&&") if cmd.strip()]
            return RunNode(
                instruction=command,
                raw_value=value,
                line_number=line_num,
                commands=commands,
            )

        elif command == "ENV":
            if "=" in value:
                k, v = value.split("=", 1)
                return EnvNode(
                    instruction=command,
                    raw_value=value,
                    line_number=line_num,
                    key=k.strip(),
                    value=v.strip(),
                )
            else:
                v_parts = value.split(None, 1)
                if len(v_parts) == 2:
                    return EnvNode(
                        instruction=command,
                        raw_value=value,
                        line_number=line_num,
                        key=v_parts[0],
                        value=v_parts[1],
                    )
                return EnvNode(
                    instruction=command,
                    raw_value=value,
                    line_number=line_num,
                    key=value,
                    value="",
                )

        elif command == "COPY":
            v_parts = value.split()
            if len(v_parts) >= 2:
                return CopyNode(
                    instruction=command,
                    raw_value=value,
                    line_number=line_num,
                    src=v_parts[:-1],
                    dst=v_parts[-1],
                )
            return CopyNode(
                instruction=command,
                raw_value=value,
                line_number=line_num,
                src=v_parts,
                dst="",
            )

        elif command == "ADD":
            v_parts = value.split()
            if len(v_parts) >= 2:
                return AddNode(
                    instruction=command,
                    raw_value=value,
                    line_number=line_num,
                    src=v_parts[:-1],
                    dst=v_parts[-1],
                )
            return AddNode(
                instruction=command,
                raw_value=value,
                line_number=line_num,
                src=v_parts,
                dst="",
            )

        elif command == "USER":
            return UserNode(
                instruction=command,
                raw_value=value,
                line_number=line_num,
                user=value.split()[0] if value else "",
            )

        elif command == "WORKDIR":
            return WorkdirNode(
                instruction=command, raw_value=value, line_number=line_num, path=value
            )

        elif command == "LABEL":
            # Very basic string map
            return LabelNode(
                instruction=command,
                raw_value=value,
                line_number=line_num,
                labels={"raw": value},
            )

        elif command == "HEALTHCHECK":
            return HealthcheckNode(
                instruction=command,
                raw_value=value,
                line_number=line_num,
                command=value,
            )

        else:
            return GenericNode(
                instruction=command, raw_value=value, line_number=line_num
            )
