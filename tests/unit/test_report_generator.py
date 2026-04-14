import pytest

from core.config import Config
from models.analysis_result import AnalysisResult
from models.issue import Issue
from report.report_generator import ReportGenerator


class Test_ReportGenerator___init__:
    def test_init(self):
        """Test init."""
        config = Config({"output": "out.html"})
        gen = ReportGenerator(config)
        assert gen._config == config


class Test_ReportGenerator_generate_html_report:
    def test_generate_success(self, tmp_path):
        """Test generate success."""
        out = tmp_path / "report.html"
        config = Config({"output": str(out)})
        result = AnalysisResult(metadata={"total_files": 1})
        result.add_issue(
            Issue(
                id="I1",
                description="d",
                severity="low",
                component="c",
                recommendation="r",
            )
        )

        gen = ReportGenerator(config)
        gen.generate_html_report(result)

        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "DockCheck" in content
        assert "I1" in content

    def test_generate_io_error(self):
        """Test generate io error."""
        # Use a path with invalid characters for Windows
        config = Config({"output": "?:/invalid/path/report.html"})
        result = AnalysisResult()
        gen = ReportGenerator(config)
        with pytest.raises(OSError):
            gen.generate_html_report(result)
