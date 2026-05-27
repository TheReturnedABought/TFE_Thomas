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
├── locales/
│   ├── en.json                        # English translation strings
│   ├── es.json                        # Spanish translation strings
│   └── fr.json                        # French translation strings
│
├── core/
│   ├── __init__.py
│   ├── analyzer.py                    # Orchestrates all sub-analyzers
│   ├── ast.py                         # AST data models for Lexer parser
│   ├── config.py                      # Runtime configuration
│   ├── i18n.py                        # Translation retrieval manager
│   ├── rules_engine.py                # Rule loading, evaluation, check registry
│   │
│   ├── parser/
│   │   └── dockerfile_parser.py       # State-machine Compiler parser for Docker files
│   │
│   └── autofix/
│       ├── __init__.py
│       ├── dockerfile_fixer.py        # Automated Dockerfile remediation logic
│       └── yaml_fixer.py              # Automated Compose/Swarm YAML remediation logic
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
│   ├── sarif_generator.py             # SAST SARIF v2.1.0 report exporter
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
    ├── conftest.py                    # Shared pytest fixtures
    │
    ├── fixtures/                      # E2E test files
    │   ├── Dockerfile.good
    │   ├── Dockerfile.bad
    │   ├── Dockerfile.edge
    │   ├── docker-compose.good.yml
    │   ├── docker-compose.bad.yml
    │   ├── docker-compose.edge.yml
    │   ├── docker-stack.good.yml
    │   ├── docker-stack.bad.yml
    │   └── docker-stack.edge.yml
    │
    ├── unit/                          # 1:1 unit testing coverage
    │   ├── __init__.py
    │   ├── test_analysis_result.py
    │   ├── test_analyzer.py
    │   ├── test_ast.py
    │   ├── test_autofix.py
    │   ├── test_cli.py
    │   ├── test_compose_analyzer.py
    │   ├── test_config.py
    │   ├── test_docker_client.py
    │   ├── test_dockerfile_analyzer.py
    │   ├── test_dockerfile_parser.py
    │   ├── test_fuzz_generators.py
    │   ├── test_i18n.py
    │   ├── test_image_analyzer.py
    │   ├── test_issue.py
    │   ├── test_performance_monitor.py
    │   ├── test_report_generator.py
    │   ├── test_rules_engine.py
    │   ├── test_sarif.py
    │   └── test_swarm_analyzer.py
    │
    ├── integration/
    │   ├── __init__.py
    │   └── test_image_analyzer.py      # Integration/pipeline tests
    │
    ├── property/
    │   └── test_ast_fuzzing.py        # Compilier-level parser property limits testing
    │
    └── monte_carlo/
        ├── __init__.py
        ├── test_chaos_prober.py       # High variance system chaos test
        └── test_grand_fuzzer.py       # Deep chaos fuzzing engine tests
```
