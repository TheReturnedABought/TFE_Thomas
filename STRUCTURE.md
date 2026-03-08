# DockCheck — File Structure

```
dockcheck/
│
├── main.py                          # Entry point CLI
│
├── cli/
│   └── cli.py                       # CLI argument parsing & command routing
│
├── core/
│   ├── analyzer.py                  # Orchestrates all sub-analyzers
│   ├── config.py                    # Config loading (CLI args / config file)
│   └── rules_engine.py              # Loads and evaluates analysis rules
│
├── analyzers/
│   ├── image_analyzer.py            # Docker image metadata + bad practices
│   ├── dockerfile_analyzer.py       # Dockerfile static analysis
│   └── compose_analyzer.py          # Docker Compose static analysis
│
├── models/
│   ├── issue.py                     # Issue dataclass (id, description, severity, component, recommendation)
│   └── analysis_result.py           # AnalysisResult dataclass (metadata, issues, severity levels, performance metrics)
│
├── report/
│   ├── report_generator.py          # HTML report generation
│   └── templates/
│       └── report.html.j2           # Jinja2 HTML report template
│
├── rules/
│   └── default_rules.json           # Default rules for image / Dockerfile / Compose analysis
│
├── utils/
│   ├── docker_client.py             # Docker SDK wrapper (read-only)
│   └── performance_monitor.py       # Timer / metrics tracking
│
├── tests/
│   ├── unit/
│   │   ├── test_image_analyzer.py
│   │   ├── test_dockerfile_analyzer.py
│   │   └── test_compose_analyzer.py
│   └── integration/
│       └── test_full_analysis.py
│
├── requirements.txt
└── README.md
```
