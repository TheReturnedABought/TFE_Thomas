import json

from core.config import Config
from models.analysis_result import AnalysisResult
from models.issue import Issue
from report.sarif_generator import SarifGenerator


class TestSarifGenerator:

    def test_sarif_mapping(self, tmp_path):
        """Test sarif mapping."""
        f = tmp_path / "report.sarif"
        config = Config({"sarif_output": str(f)})
        gen = SarifGenerator(config)

        issue1 = Issue(
            id="DF-001",
            description="desc",
            severity="critical",
            component="dock.df",
            recommendation="fix",
        )
        issue2 = Issue(
            id="CMD-001",
            description="desc2",
            severity="low",
            component="cmd.df",
            recommendation="fix2",
        )
        result = AnalysisResult(issues=[issue1, issue2])

        gen.generate(result)

        with open(f, "r") as r:
            payload = json.load(r)

        assert payload["version"] == "2.1.0"
        results = payload["runs"][0]["results"]
        assert len(results) == 2

        assert results[0]["ruleId"] == "DF-001"
        assert results[0]["level"] == "error"
        assert results[1]["ruleId"] == "CMD-001"
        assert results[1]["level"] == "note"

        rules = payload["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2
        assert rules[0]["id"] == "DF-001"
        assert rules[0]["name"] == "DF001"

    def test_duplicate_rules_collapse(self, tmp_path):
        """Test duplicate rules collapse."""
        f = tmp_path / "report2.sarif"
        gen = SarifGenerator(Config({"sarif_output": str(f)}))

        issue1 = Issue(
            id="DF-001",
            description="desc",
            severity="medium",
            component="dock.df",
            recommendation="fix",
        )
        issue2 = Issue(
            id="DF-001",
            description="desc",
            severity="medium",
            component="dock2.df",
            recommendation="fix",
        )

        gen.generate(AnalysisResult(issues=[issue1, issue2]))

        with open(f, "r") as r:
            payload = json.load(r)

        rules = payload["runs"][0]["tool"]["driver"]["rules"]
        results = payload["runs"][0]["results"]

        # Results remain duplicate entries (2) since they occur in different files/locations
        assert len(results) == 2
        # But Rules are deduped to 1
        assert len(rules) == 1
