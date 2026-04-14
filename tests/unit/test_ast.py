"""
Validations for AST pure structural elements.
"""

from core.ast import DockerNode, FromNode, RunNode


class TestASTNodes:
    def test_immutable_properties(self):
        """Test immutable properties."""
        node = FromNode(
            instruction="FROM",
            raw_value="alpine:latest",
            line_number=1,
            image="alpine",
            tag="latest",
        )
        assert node.instruction == "FROM"
        assert node.line_number == 1

        # Test defaults
        run = RunNode(instruction="RUN", raw_value="echo", line_number=2)
        assert run.commands == []
