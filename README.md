# DockCheck

> Static analysis tool for Docker images, Dockerfiles, Docker Compose files, and Docker Swarm stacks.  
> TFE — EPHEC Haute École | Thomas Girboux | Rapporteur : Jonathan Noël | 2026

---

## Table of Contents

- [Overview](#overview)
- [Python Engineering Best Practices](#python-engineering-best-practices)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Rules Engine](#rules-engine)
- [HTML Report](#html-report)
- [Running Tests](#running-tests)
- [Limitations](#limitations)

---

## Overview

DockCheck is a command-line tool that performs **static analysis** of Docker environments without requiring a running daemon (except for image metadata extraction). It targets DevOps engineers and system integrators who need to automate quality and security checks on their Docker assets.

It fills a gap left by existing tools:

| Tool | Dockerfile | Compose | Swarm | HTML report |
|------|-----------|---------|-------|-------------|
| Hadolint | ✅ | ❌ | ❌ | ❌ |
| Dockle | ❌ | ❌ | ❌ | ❌ |
| Trivy | Partial | ❌ | ❌ | ❌ |
| **DockCheck** | **✅** | **✅** | **✅** | **✅** |

---

## Python Engineering Best Practices

This project was built to demonstrate professional Python software engineering patterns:
- **Test-Driven Development & Fuzzing:** Achieves ~1.14:1 test-to-source code ratio (>90% coverage) using `pytest`. Employs property-based fuzzing (`hypothesis`) and Monte Carlo limits testing.
- **Compiler Level AST Manipulation:** Implements a state-machine Lexer enabling non-destructive reading of Dockerfiles without regex fragilities.
- **Immutable Data Structures:** Built strictly around Python `dataclass` models (`Issue`, `AnalysisResult`).
- **Modularity:** High separation of concerns (`core`, `CLI`, `orchestrator`, `parsers`), making extending the engine with custom frameworks safe and atomic.
- **Type Hinting:** Fully type-hinted methods throughout the architecture ensuring maximum execution safety.

---

## Features

- **Dockerfile analysis** — detects bad practices: unversioned base images, running as root, multiple consecutive `RUN` instructions, `ADD` instead of `COPY`, missing `WORKDIR`, split `apt-get` calls.
- **Docker image analysis** — extracts metadata (size, layers, base image, labels, env vars) and flags security issues via the Docker SDK (read-only).
- **Docker Compose analysis** — validates service configurations: unversioned images, root users, hardcoded secrets in environment variables, sensitive exposed ports, duplicate services.
- **Docker Swarm analysis** — validates Swarm stack deployment configurations: missing replicas, resource limits/reservations, restart policies, placement constraints, rolling update configs, secrets management, image versioning, network isolation, and healthchecks.
- **HTML report generation** — structured report with summary dashboard, issues ranked by severity, and concrete recommendations.
- **Severity filtering** — `--severity low|medium|critical` threshold for CI/CD gate usage.
- **CI/CD AutoFix Engine (`--fix`)** — Implements an automated remediation layer replacing vulnerable AST structures with safe nodes natively without stripping configuration layouts.
- **SARIF Code Scanning Export** — Generates `dockcheck_report.sarif` mapping securely onto OASIS v2.1.0 specifications for immediate ingestion into **GitHub Advanced Security** and **GitLab SAST** dashboards.
- **Compiler Level Parse Integrity** — Implements pure-state-machine Dockerfile AST generation guaranteeing 100% resilience against multiline syntax formatting failures structurally tested against 10,000 bounds of fuzzed hypothesis noise limiters.
- **i18n Localization (`--lang fr`)** — Complete decoupling of english strings scaling natively to generalized i18n JSON locales (supports native French and Spanish out of the box).
- **Exit codes** — returns `0` (no issues) or `1` (issues found) for pipeline integration.
- **Custom rules** — supports a custom `rules.json` file via `--rules`.

---

## Architecture

DockCheck follows a clean layered architecture:

```
CLI (argparse)
    └── Config
         └── Analyzer (orchestrator)
              ├── DockerfileAnalyzer  ──► RulesEngine ──► Issue[]
              ├── ComposeAnalyzer     ──► RulesEngine ──► Issue[]
              ├── SwarmAnalyzer       ──► RulesEngine ──► Issue[]
              └── DockerImageAnalyzer ──► RulesEngine ──► Issue[]
                        └── AnalysisResult
                                └── ReportGenerator ──► report.html
```

All analysis is **read-only** and **isolated** from the host system. No container is executed during analysis.

---

## Installation

**Requirements:** Python 3.10+, Docker (only needed for image analysis)

```bash
# Clone the repository
git clone https://github.com/TheReturnedABought/dockcheck.git
cd dockcheck

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Analyse a Dockerfile

```bash
python main.py dockerfile ./Dockerfile
python main.py --output report.html --severity medium dockerfile ./Dockerfile
```

### Analyse a Docker Compose file

```bash
python main.py compose ./docker-compose.yml
python main.py --severity critical compose ./docker-compose.yml
```

### Analyse a Docker Swarm stack file

```bash
python main.py swarm ./docker-stack.yml
python main.py --output swarm_report.html swarm ./docker-stack.yml
```

### Analyse a local Docker image

```bash
python main.py image nginx:latest
python main.py --output myapp_report.html image myapp:1.0
```

### Run all analyses at once

```bash
python main.py all \
  --image myapp:1.0 \
  --dockerfile ./Dockerfile \
  --compose ./docker-compose.yml \
  --swarm ./docker-stack.yml \
  --output full_report.html
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--output`, `-o` | `dockcheck_report.html` | Path for the HTML report |
| `--sarif-output` | `dockcheck_report.sarif` | Generates a SARIF file alongside HTML for CI/CD SAST dashboard aggregation |
| `--fix` | false | Automatically mitigates simple static issues natively. For complex issues, outputs a warning explicitly flagged for manual engineering review. |
| `--lang` | `en` | Overrides reporting strings localization (supports `en`, `fr`, 'es') |
| `--severity`, `-s` | `low` | Minimum severity to report (`low`, `medium`, `critical`) |
| `--no-report` | false | Skip HTML generation, print summary only |
| `--rules` | built-in | Path to a custom rules JSON file |

---

## Custom Rules & AutoFixing

DockCheck supports injecting custom rules through standard JSON schemas using the `--rules` flag. By adding a declarative `"autofix"` metadata block, your custom rules become natively supported by the `--fix` automated mitigation engine!

### Defining a Custom Rule

Create a `custom_rules.json` file and pass it via `--rules custom_rules.json`. The syntax allows targeting any string natively. 

```json
{
  "rules": [
    {
      "id": "CUST-001",
      "component": "dockerfile",
      "description": "Always replace 'python:latest' with 'python:slim'",
      "severity": "low",
      "check": "base_image_unversioned",
      "recommendation": "Use slim variant.",
      "autofix": {
        "supported": true,
        "strategy": "replace_string",
        "target": ":latest",
        "replacement": ":slim"
      }
    }
  ]
}
```

The engine currently supports two fundamental structural strategies natively without requiring Python extensions:
- **`replace_string` (Dockerfile)**: Parses and substitutes direct text matching inside active statements.
- **`set_key` (Compose/Swarm YAML)**: Blindly assigns the key-value dictionary mappings natively to bypass node limits.

---

## Project Structure

```text
dockcheck/
├── main.py                        # Entry point
├── requirements.txt               # Project dependencies
├── locales/
│   └── en.json                    # i18n localization definitions
├── cli/
│   └── cli.py                     # Argument parsing & routing
├── core/
│   ├── analyzer.py                # Orchestrates sub-analyzers
│   ├── ast.py                     # Abstract Syntax Tree Data Classes (Lexer)
│   ├── config.py                  # Runtime configuration
│   ├── i18n.py                    # Localization and translation getter framework
│   ├── rules_engine.py            # Rule loading & evaluation
│   └── parser/
│       └── dockerfile_parser.py   # State-machine Compiler parser for Docker files
├── analyzers/
│   ├── dockerfile_analyzer.py     # Dockerfile static analysis (ingests AST)
│   ├── image_analyzer.py          # Docker image metadata & checks
│   ├── compose_analyzer.py        # Docker Compose static analysis
│   └── swarm_analyzer.py          # Docker Swarm stack analysis
├── models/
│   ├── issue.py                   # Issue dataclass
│   └── analysis_result.py         # AnalysisResult dataclass
├── report/
│   ├── report_generator.py        # HTML report generation (Jinja2)
│   ├── sarif_generator.py         # Standard SAST SARIF v2.1.0 formatted exports 
│   └── templates/
│       └── report.html.j2         # Self-contained HTML template
├── rules/
│   └── default_rules.json         # Built-in rules (DF-*, IMG-*, DC-*, SW-*)
├── utils/
│   ├── docker_client.py           # Docker SDK wrapper (read-only)
│   └── performance_monitor.py     # Wall-clock timer
└── tests/
    ├── conftest.py                # Shared pytest fixtures
    ├── fixtures/                  # E2E test files
    ├── unit/                      # 1:1 source-to-test mapping
    │   ├── test_analysis_result.py
    │   ├── test_analyzer.py
    │   ├── test_ast.py
    │   ├── test_compose_analyzer.py
    │   ├── test_config.py
    │   ├── test_docker_client.py
    │   ├── test_dockerfile_analyzer.py
    │   ├── test_dockerfile_parser.py
    │   ├── test_i18n.py
    │   ├── test_image_analyzer.py
    │   ├── test_issue.py
    │   ├── test_performance_monitor.py
    │   ├── test_report_generator.py
    │   ├── test_rules_engine.py
    │   ├── test_sarif.py
    │   └── test_swarm_analyzer.py
    ├── integration/
    │   └── test_image_analyzer.py # Requires Docker daemon
    ├── property/
    │   └── test_ast_fuzzing.py    # Extremely aggressive fuzzer on the compiler theory level limits via Hypothesis.
    └── monte_carlo/
        └── test_grand_fuzzer.py   # High variance system chaos framework
```

---

## Rules Engine

Rules are defined in `rules/default_rules.json`. Each rule has an `id`, `severity`, `description`, `recommendation`, and a `check` key that maps to an evaluator function.

**Built-in rules:**

### Dockerfile rules (DF-*)

| ID | Severity | Description |
|----|----------|-------------|
| DF-001 | high | Unversioned base image (`:latest` or no tag) (Source: CIS 4.2 / Docker Best Practices) |
| DF-002 | high | Running as root (no `USER` or `USER root`) (Source: CIS 4.1 / IBM) |
| DF-003 | low | Multiple consecutive `RUN` instructions (Source: Docker Best Practices) |
| DF-004 | medium | `ADD` used instead of `COPY` (Source: CIS 4.3 / Docker Best Practices) |
| DF-005 | low | Missing `WORKDIR` (Source: Docker Best Practices) |
| DF-006 | low | Split `apt-get update` / `apt-get install` (Source: Docker Best Practices) |
| DF-007 | medium | No HEALTHCHECK instruction defined (Source: CIS 4.6 / IBM) |
| DF-008 | low | apt-get install used without --no-install-recommends (Source: CIS / 0xfujin) |
| DF-009 | low | pip install used without --no-cache-dir (Source: 0xfujin) |
| DF-010 | low | apk add used without --no-cache (Source: Alpine Best Practices) |
| DF-011 | low | yum install used without repository cleanup (Source: RedHat Best Practices) |
| DF-012 | low | curl used without silent-fail flags (-fSL) (Source: Docker Best Practices) |
| DF-013 | low | wget used without quiet-output stream bindings (Source: Docker Best Practices) |
| DF-014 | low | sudo executed during Docker build (Source: CIS 4.1 / Docker Best Practices) |
| DF-015 | medium | apt-get install used without footprint cleanup (Source: 10 Docker Best Practices) |
| DF-016 | low | No EXPOSE network port mappings declared (Source: Docker Best Practices) |
| DF-018 | low | Inline path traversals (cd) rather than deterministic WORKDIR (Source: Docker Best Practices) |
| DF-019 | low | npm install used without clearing node caching (Source: Node.js Best Practices) |
| DF-020 | medium | System-wide package updates (e.g., apt-get upgrade) (Source: CIS 4.7) |
| DF-021 | high | Image potentially retains setuid/setgid permissions (Source: CIS 4.8) |
| DF-022 | high | Dockerfile uses ARG for sensitive data (Source: Docker Sec) |
| DF-023 | medium | ENTRYPOINT is in shell form rather than exec form (Source: Docker Sec) |
| DF-024 | medium | CMD is in shell form rather than exec form (Source: Docker Sec) |
| DF-025 | medium | EXPOSE instruction contains port 22 (SSH) (Source: NIST SP 800-190) |
| DF-026 | medium | wget or curl is used without a checksum validation pipe (Source: SLSA) |
| DF-027 | medium | apk add is used without pinning package versions (Source: CIS) |
| DF-028 | medium | apt-get install is used without pinning package versions (Source: CIS) |
| DF-029 | medium | HEALTHCHECK interval is missing or set to zero (Source: CIS 4.6) |
| DF-030 | low | COPY is followed by a RUN chown command (Source: Docker Sec) |
| DF-031 | high | Base image is pulled from an untrusted generic public registry path (Source: CIS 4.2) |
| DF-032 | medium | Dockerfile lacks multi-stage build structure for compiled languages (Source: Docker Sec) |
| DF-033 | high | User is switched to root later in the Dockerfile (Source: NIST SP 800-190) |
| DF-034 | medium | Use of unencrypted HTTP protocols in package managers (Source: NIST SP 800-190) |
| DF-035 | low | WORKDIR is relative, not absolute (Source: DL3000) |
| DF-036 | medium | gem install without version pinning (Source: DL3028) |
| DF-037 | medium | npm install without version pinning (Source: DL3016) |
| DF-038 | low | yum install without -y (Source: DL3030) |
| DF-039 | medium | yum install without version pinning (Source: DL3033) |
| DF-040 | low | zypper install without -y (Source: DL3034) |
| DF-041 | low | zypper clean missing (Source: DL3036) |
| DF-042 | medium | zypper install without version pinning (Source: DL3037) |
| DF-043 | low | dnf install without -y (Source: DL3038) |
| DF-044 | low | dnf clean all missing (Source: DL3040) |
| DF-045 | medium | dnf install without version pinning (Source: DL3041) |
| DF-046 | low | Multiple HEALTHCHECK instructions used (Source: DL3012) |
| DF-047 | low | Invalid port range in EXPOSE (Source: DL3011) |
| DF-048 | low | COPY with >2 args doesn't end with / (Source: DL3021) |
| DF-049 | medium | COPY --from references non-existent stage (Source: DL3022) |
| DF-050 | medium | FROM stage aliases are not unique (Source: DL3024) |
| DF-051 | low | Use of apt instead of apt-get (Source: DL3027) |

### Image rules (IMG-*)

| ID | Severity | Description |
|----|----------|-------------|
| IMG-001 | high | Missing image labels (Source: Docker Best Practices) |
| IMG-002 | critical | Sensitive data in environment variables (Source: CIS 4.10 / NIST SP 800-190) |
| IMG-003 | low | Excessive layer count (> 20) (Source: Docker Best Practices) |
| IMG-004 | high | Image runs as root (Source: CIS 4.1 / NIST SP 800-190) |
| IMG-005 | high | Unversioned base image (Source: CIS 4.2) |
| IMG-006 | low | Total image payload significantly exceeds 1GB limit (Source: Docker Best Practices) |
| IMG-008 | high | Scratch infrastructure defaults silently back to unregulated ROOT mappings (Source: NIST SP 800-190) |
| IMG-009 | high | Production configurations rely implicitly upon 'latest' tag allocations (Source: CIS 4.2) |
| IMG-010 | medium | Constructed object artifacts miss active daemon process triggers (CMD/ENTRYPOINT) (Source: Docker Best Practices) |
| IMG-011 | medium | Image has no healthcheck metadata (Source: CIS 4.6) |
| IMG-012 | high | Image signed by Docker Content Trust / Cosign is missing (Source: CIS 4.5) |
| IMG-013 | medium | Image history contains ADD instructions (Source: CIS 4.3) |
| IMG-014 | medium | Image history contains system upgrade commands (Source: CIS 4.7) |
| IMG-016 | critical | Image history contains sensitive keywords (password, secret) (Source: CIS 4.10) |
| IMG-017 | high | USER is explicitly set to root or 0 (Source: CIS 4.1) |
| IMG-018 | low | Image has suspiciously large layers (> 500MB per layer) (Source: Docker Best Practices) |
| IMG-020 | medium | Image exposes ports on all interfaces (0.0.0.0) in Expose configurations (Source: NIST SP 800-190) |
| IMG-022 | medium | Image configuration contains debugging environment variables (Source: OWASP Docker Security) |
| IMG-023 | medium | Image lacks ENTRYPOINT but has CMD, or vice-versa (Source: Docker Best Practices) |
| IMG-025 | medium | Image metadata contains overly permissive Volumes without security profiles (Source: NIST SP 800-190) |
| IMG-026 | medium | Image layers contain wget/curl without checksum validation (Source: SLSA) |
| IMG-028 | medium | Missing SBOM (Source: Anchore/Syft) |
| IMG-029 | medium | Missing SLSA provenance attestation (Source: SLSA) |
| IMG-030 | low | Full OS base when distroless would suffice (Source: Google Distroless) |
| IMG-031 | high | Debugging tools found in layers (Source: Docker Hardened) |
| IMG-032 | high | Shell found in a production image layer (Source: Docker Hardened) |
| IMG-033 | medium | Package managers found in layers (Source: Docker Hardened) |

### Compose rules (DC-*)

| ID | Severity | Description |
|----|----------|-------------|
| DC-001 | high | Service uses `:latest` or untagged image (Source: Docker Best Practices) |
| DC-002 | high | Service runs as root or has no `user` (Source: CIS Docker Benchmark) |
| DC-003 | critical | Hardcoded secret in environment variables (Source: Docker Sec) |
| DC-004 | medium | Port exposed on all interfaces or sensitive port (Source: NIST SP 800-190) |
| DC-005 | low | Duplicate service images (Source: TFE Base) |
| DC-006 | critical | Service runs in privileged mode (Source: IBM Docker Security) |
| DC-007 | medium | Volume not mounted as read-only (Source: IBM Docker Security) |
| DC-008 | medium | Service missing declarative restart parameter (Source: TFE Base) |
| DC-009 | medium | Service missing a localized healthcheck configuration (Source: Docker Best Practices) |
| DC-010 | critical | Service assigns container to host network mode (Source: CIS Docker Benchmark) |
| DC-011 | critical | Service breaks PID namespace via host mapping (Source: NIST SP 800-190) |
| DC-012 | low | Service ignores structured resource memory/CPU limitations (Source: Docker Sec) |
| DC-014 | high | SYS_ADMIN or ALL capability escalation granted (Source: CIS Docker Benchmark) |
| DC-015 | critical | Inter-Process Communication attached directly to Host (Source: NIST SP 800-190) |
| DC-016 | low | Fixed deployment bounded by hardcoded MAC identifiers (Source: TFE Base) |
| DC-017 | medium | DNS queries strictly overridden skipping internal resolvers (Source: Docker Best Practices) |
| DC-018 | high | Service lacks cap_drop: - ALL (Source: CIS Docker Benchmark) |
| DC-019 | high | Service lacks security_opt: - no-new-privileges:true (Source: CIS Docker Benchmark) |
| DC-020 | high | Service mounts .env or sensitive files as volumes (Source: NIST SP 800-190) |
| DC-021 | high | Service does not configure a custom network (Source: CIS Docker Benchmark) |
| DC-022 | critical | Service exposes Docker socket /var/run/docker.sock (Source: CIS Docker Benchmark) |
| DC-023 | high | Service lacks read_only: true (Source: CIS Docker Benchmark) |
| DC-024 | low | Service uses network_mode: bridge explicitly (Source: Docker Best Practices) |
| DC-025 | high | Service mounts the host root / directory (Source: CIS Docker Benchmark) |
| DC-026 | high | Service mounts the host /etc directory (Source: CIS Docker Benchmark) |
| DC-027 | high | Service uses env_file instead of Docker secrets (Source: Docker Best Practices) |
| DC-028 | medium | Service lacks a logging driver configuration with max-size (Source: Docker Best Practices) |
| DC-029 | medium | Service tmpfs mounts lack explicit size limits (Source: Docker Best Practices) |
| DC-030 | medium | Service binds to privileged ports (<1024) (Source: NIST SP 800-190) |
| DC-031 | medium | Service lacks explicit depends_on for startup ordering (Source: Docker Best Practices) |
| DC-032 | critical | Service uses cgroup_parent which can bypass isolation (Source: Docker Security) |
| DC-033 | critical | Service defines userns_mode: host breaking user namespace isolation (Source: CIS Docker Benchmark) |

### Swarm rules (SW-*)

| ID | Severity | Description |
|----|----------|-------------|
| SW-001 | medium | Service deployed globally instead of replicated (Source: Docker Best Practices) |
| SW-002 | medium | Service bound to manager nodes specifically (Source: CIS Docker Benchmark) |
| SW-003 | medium | Port mappings exposed without routing mesh declarations (Source: TFE Base) |
| SW-004 | medium | Overlay network explicitly disabled for multi-host topology (Source: NIST SP 800-190) |
| SW-005 | medium | Node scheduling enforces strict single-node affinities (Source: CIS Docker Benchmark) |
| SW-006 | medium | Volumes configured via host-paths rather than managed structures (Source: NIST SP 800-190) |
| SW-007 | critical | Secrets bound into image rootfs instead of ephemeral memory (Source: CIS Docker Benchmark) |
| SW-008 | high | Cluster update configuration ignores parallelism thresholds (Source: Docker Best Practices) |
| SW-009 | high | Rollback configuration lacks determinism (Source: Docker Best Practices) |
| SW-010 | medium | Service overrides host-level IPC configurations (Source: CIS Docker Benchmark) |
| SW-011 | medium | Application explicitly links to Docker Unix socket (Source: NIST SP 800-190) |
| SW-012 | critical | Service assumes implicit registry resolution context (Source: TFE Base) |
| SW-013 | medium | Explicit DNS namespace hijacking across Swarm services (Source: CIS Docker Benchmark) |
| SW-014 | medium | Memory reservations established without upper bound restrictions (Source: Docker Sec) |
| SW-015 | medium | Processor reservations defined without scheduler enforcement (Source: Docker Sec) |
| SW-016 | medium | Unverified container metadata propagated to cluster state (Source: NIST SP 800-190) |
| SW-017 | medium | Logging driver defaults override centralized cluster transport (Source: Docker Best Practices) |
| SW-018 | critical | Swarm manager auto-lock mode not explicitly handled (Source: CIS Docker Benchmark) |
| SW-019 | critical | Swarm overlay network is unencrypted (Source: CIS Docker Benchmark) |
| SW-020 | high | Swarm service uses host-bound volume mounts (Source: NIST SP 800-190) |
| SW-021 | medium | Swarm nodes missing placement constraints / role separation (Source: NIST SP 800-190) |
| SW-022 | critical | Swarm manager binding to untrusted / wildcard interfaces (0.0.0.0) (Source: CIS Docker Benchmark) |
| SW-023 | medium | Swarm service does not declare rolling update parallelism limits (Source: Docker Best Practices) |
| SW-024 | high | Swarm secret mapped to container filesystem improperly (Source: NIST SP 800-190) |
| SW-025 | critical | Swarm service exposes management API ports (Source: CIS Docker Benchmark) |
| SW-026 | medium | Swarm service lacks declarative CPU limits (Source: Docker Best Practices) |
| SW-027 | medium | Swarm service lacks declarative memory limits (Source: Docker Best Practices) |
| SW-028 | low | Swarm service deployment uses global mode (Source: Docker Best Practices) |
| SW-029 | high | Swarm config mapped via env variables instead of Docker Configs (Source: Docker Best Practices) |
| SW-030 | low | Swarm service ignores endpoint_mode dnsrr for internal discovery (Source: Docker Best Practices) |
| SW-031 | high | Swarm service uses --cap-add=ALL (Source: CIS Docker Benchmark) |
| SW-032 | medium | Swarm services bypassing routing mesh using explicit host ports (Source: Docker Security) |
| SW-033 | medium | Swarm service deployed without healthcheck propagation (Source: CIS Docker Benchmark) |

You can add custom rules by pointing `--rules` to your own JSON file following the same schema.

---

## HTML Report

The generated report contains:

- **Summary dashboard** — total issues count with severity breakdown cards.
- **Metadata** — target analysed, analysis timestamp.
- **Issues** — each issue with its ID, severity badge, description, and component reference.
- **Recommendations** — grouped actionable guidance.
- **Performance** — analysis duration.

Reports are self-contained HTML files (inline CSS, dark theme) suitable for archiving, sharing, or attaching to CI/CD pipeline artifacts.

---

## Running Tests

```bash
# All tests (Unit tests, 10,000 bound property bounds, and E2E)
pytest -v

# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# With coverage (94%+ coverage)
pytest --cov=. --cov-report=term-missing
```

Tests use mocked file I/O and a mocked Docker SDK — no live Docker daemon is required to run the test suite.

---

## Limitations

- **No runtime analysis** — issues that only appear during container execution (network conflicts, runtime errors) cannot be detected.
- **No CVE scanning** — DockCheck focuses on best-practice and configuration checks, not vulnerability databases. Use Trivy or Grype alongside DockCheck for CVE coverage.
- **`.env` files** — dynamic values from external `.env` files are not resolved unless DockCheck has access to them.
- **Large images** — parsing metadata for very large, multi-layer images may be CPU and memory intensive.
- **Docker Desktop (Windows)** — minor behavioural differences compared to Linux may affect image metadata extraction in some edge cases.
- **Swarm live state** — DockCheck analyses the static stack file, not the live cluster state. Drift between the file and deployed services is not detected.

---

## Sources & References

The rules and best practices implemented in DockCheck are derived from industry-standard security benchmarks and community guides:

- **[IBM Best Practices for Docker Security](https://www.ibm.com/docs/en/cloud-paks/cp-data/4.0?topic=security-docker-best-practices)** — Foundation for root user checks, healthchecks, and privileged mode alerts.
- **[10 Docker Best Practices for Security](https://blog.aquasec.com/docker-security-best-practices)** — Basis for `ADD` vs `COPY`, `apt-get` optimization, and layer reduction.
- **[AccuWeb Swarm Recommendations](https://www.accuwebhosting.com/blog/docker-swarm-best-practices/)** — Basis for resource limits, secrets management, and network isolation rules in Swarm.
- **[Official Docker Documentation](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)** — General syntax and structural standards.

- **NIST Application Container Security Guide (SP 800-190)** — Foundation for host PID, IPC, and network mode mapping strict isolation boundaries.
- **Node.js Docker Best Practices** — Basis for cache clearing requirements inside 'npm' runtime construction.
- **Docker Official Swarm Update Configurations** — Recommended metrics guiding zero-downtime rolling update 'order' priorities and 'delay' limits.

---

## License

MIT — see [LICENSE](LICENSE).
