# DockCheck — Project Structure

```
dockcheck/
├── main.py                            # CLI entry point
├── requirements.txt                   # Python dependencies
│
├── cli/
│   ├── __init__.py
│   └── cli.py                         # Argument parsing & routing
│
├── core/
│   ├── __init__.py
│   ├── analyzer.py                    # Orchestrates all sub-analyzers
│   ├── config.py                      # Runtime configuration
│   └── rules_engine.py               # Rule loading, evaluation, check registry
│
├── analyzers/
│   ├── __init__.py
│   ├── dockerfile_analyzer.py         # Dockerfile static analysis
│   ├── image_analyzer.py              # Docker image metadata extraction & checks
│   ├── compose_analyzer.py            # Docker Compose static analysis
│   └── swarm_analyzer.py              # Docker Swarm stack analysis
│
├── models/
│   ├── __init__.py
│   ├── issue.py                       # Issue dataclass
│   └── analysis_result.py             # AnalysisResult dataclass
│
├── report/
│   ├── __init__.py
│   ├── report_generator.py            # HTML report generation (Jinja2)
│   └── templates/
│       └── report.html.j2             # Self-contained HTML template (dark theme)
│
├── rules/
│   └── default_rules.json             # Built-in rules: DF-*, IMG-*, DC-*, SW-*
│
├── utils/
│   ├── __init__.py
│   ├── docker_client.py               # Docker SDK wrapper (read-only)
│   └── performance_monitor.py         # Wall-clock timer
│
└── tests/
    ├── __init__.py
    ├── conftest.py                    # Shared pytest fixtures & smart_mock_open
    ├── fixtures/                      # E2E test files
    │   ├── Dockerfile.good
    │   ├── Dockerfile.bad
    │   ├── Dockerfile.edge
    │   ├── docker-compose.good.yml
    │   ├── docker-compose.bad.yml
    │   ├── docker-stack.good.yml
    │   └── docker-stack.bad.yml
    ├── unit/
    │   ├── __init__.py
    │   ├── test_dockerfile_analyzer.py
    │   ├── test_compose_analyzer.py
    │   ├── test_swarm_analyzer.py
    │   └── test_full_analysis.py      # Integration/pipeline tests
    └── integration/
        ├── __init__.py
        └── test_image_analyzer.py
```
