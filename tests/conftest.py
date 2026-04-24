"""
tests/conftest.py — Shared pytest fixtures for all DockCheck tests.

Provides reusable Dockerfile, Compose, Swarm, and Image metadata fixtures
used across unit and integration tests.
"""

import io

import pytest

# The real open function, saved before any patching
_real_open = open


def smart_mock_open(target_filename: str, fake_content: str):
    """
    Return a side_effect function for patching builtins.open that:
      - Returns fake_content for any path ending with target_filename
      - Delegates to real open() for all other files (e.g. default_rules.json)
    """

    def _side_effect(path, *args, **kwargs):
        path_str = str(path)
        if path_str.endswith(target_filename) or path_str == target_filename:
            return io.StringIO(fake_content)
        return _real_open(path, *args, **kwargs)

    return _side_effect


# ===========================================================================
# Dockerfile fixtures
# ===========================================================================


@pytest.fixture
def dockerfile_good():
    """A clean Dockerfile that should produce zero issues."""
    return (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "COPY requirements.txt .\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends curl \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
        "RUN pip install --no-cache-dir -r requirements.txt\n"
        "COPY . .\n"
        "USER appuser\n"
        "HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1\n"
        'CMD ["python", "main.py"]\n'
    )


@pytest.fixture
def dockerfile_bad_root():
    """Dockerfile with :latest tag and no USER instruction (runs as root)."""
    return "FROM python:latest\n" "COPY . /app\n" 'CMD ["python", "app.py"]\n'


@pytest.fixture
def dockerfile_bad_latest():
    """Dockerfile that explicitly uses :latest and USER root."""
    return (
        "FROM ubuntu:latest\n"
        "RUN apt-get update && apt-get install -y python3\n"
        "RUN pip install flask\n"
        "COPY . /app\n"
        "USER root\n"
        'CMD ["python3", "app.py"]\n'
    )


@pytest.fixture
def dockerfile_multi_run():
    """Dockerfile with multiple consecutive RUN instructions (non-optimised layers)."""
    return (
        "FROM node:18\n"
        "RUN apt-get update\n"
        "RUN apt-get install -y curl\n"
        "RUN apt-get install -y git\n"
        "COPY . /app\n"
        "USER node\n"
        'CMD ["node", "server.js"]\n'
    )


# ===========================================================================
# Docker Compose fixtures
# ===========================================================================


@pytest.fixture
def compose_good():
    """Clean compose file — pinned versions, non-root users, no secrets in env."""
    return (
        "version: '3.8'\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "    ports:\n"
        "      - '8080:80'\n"
        "    user: '1000'\n"
        "    restart: unless-stopped\n"
        "    healthcheck:\n"
        "      test: ['CMD', 'curl', '-f', 'http://localhost']\n"
        "  db:\n"
        "    image: postgres:15\n"
        "    user: '999'\n"
        "    restart: always\n"
        "    healthcheck:\n"
        "      test: ['CMD', 'pg_isready']\n"
        "    environment:\n"
        "      POSTGRES_PASSWORD_FILE: /run/secrets/db_password\n"
    )


@pytest.fixture
def compose_bad_latest():
    """Compose with :latest tags and plaintext passwords."""
    return (
        "version: '3.8'\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:latest\n"
        "    user: '1000'\n"
        "    ports:\n"
        "      - '80:80'\n"
        "  db:\n"
        "    image: postgres\n"
        "    user: '999'\n"
        "    environment:\n"
        "      POSTGRES_PASSWORD: supersecret\n"
    )


@pytest.fixture
def compose_bad_root():
    """Compose with root user and port exposed on all interfaces."""
    return (
        "version: '3.8'\n"
        "services:\n"
        "  app:\n"
        "    image: myapp:1.0\n"
        "    user: 'root'\n"
        "    privileged: true\n"
        "    ports:\n"
        "      - '0.0.0.0:22:22'\n"
        "    volumes:\n"
        "      - './data:/data'\n"
    )


@pytest.fixture
def compose_missing_user():
    """Compose with no 'user' key defined."""
    return (
        "version: '3.8'\n"
        "services:\n"
        "  app:\n"
        "    image: myapp:1.0\n"
        "    ports:\n"
        "      - '8080:80'\n"
    )


# ===========================================================================
# Docker Swarm fixtures
# ===========================================================================


@pytest.fixture
def swarm_good():
    """Clean Swarm stack with all best-practice configurations."""
    return (
        "version: '3.8'\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "    user: '1000'\n"
        "    deploy:\n"
        "      replicas: 3\n"
        "      resources:\n"
        "        limits:\n"
        "          cpus: '0.5'\n"
        "          memory: 256M\n"
        "        reservations:\n"
        "          cpus: '0.25'\n"
        "          memory: 128M\n"
        "      restart_policy:\n"
        "        condition: on-failure\n"
        "        delay: 5s\n"
        "        max_attempts: 3\n"
        "      placement:\n"
        "        constraints:\n"
        "          - node.role == worker\n"
        "      update_config:\n"
        "        parallelism: 1\n"
        "        delay: 10s\n"
        "        order: start-first\n"
        "    secrets:\n"
        "      - db_password\n"
        "    networks:\n"
        "      - frontend\n"
        "    stop_grace_period: 30s\n"
        "    healthcheck:\n"
        "      test: ['CMD', 'curl', '-f', 'http://localhost']\n"
        "      interval: 30s\n"
        "      timeout: 10s\n"
        "      retries: 3\n"
        "    logging:\n"
        "      driver: 'json-file'\n"
        "      options:\n"
        "        max-size: '10m'\n"
        "        max-file: '3'\n"
        "networks:\n"
        "  frontend:\n"
        "    driver: overlay\n"
        "secrets:\n"
        "  db_password:\n"
        "    external: true\n"
    )


@pytest.fixture
def swarm_bad():
    """Swarm stack with multiple issues: no replicas, no resource limits,
    no restart policy, secrets in env vars, :latest image, default network,
    no healthcheck, no update_config, no placement."""
    return (
        "version: '3.8'\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:latest\n"
        "    environment:\n"
        "      DB_PASSWORD: supersecret\n"
        "      API_KEY: abc123\n"
        "    privileged: true\n"
        "    deploy:\n"
        "      mode: replicated\n"
    )


@pytest.fixture
def swarm_partial():
    """Swarm stack with some issues (partial config)."""
    return (
        "version: '3.8'\n"
        "services:\n"
        "  api:\n"
        "    image: myapi:2.1\n"
        "    user: '1000'\n"
        "    deploy:\n"
        "      replicas: 2\n"
        "      resources:\n"
        "        limits:\n"
        "          memory: 512M\n"
        "      restart_policy:\n"
        "        condition: any\n"
        "    networks:\n"
        "      - backend\n"
        "networks:\n"
        "  backend:\n"
        "    driver: overlay\n"
    )


# ===========================================================================
# Docker Image metadata fixtures
# ===========================================================================


@pytest.fixture
def mock_image_metadata():
    """Clean image metadata — no issues expected."""
    return {
        "id": "sha256:abc123",
        "tags": ["myapp:1.0"],
        "size_mb": 120.5,
        "num_layers": 7,
        "base_image": "python:3.11-slim",
        "labels": {"maintainer": "dev@example.com"},
        "env_vars": ["PATH=/usr/local/bin", "PYTHONDONTWRITEBYTECODE=1"],
        "user": "appuser",
        "architecture": "amd64",
        "os": "linux",
        "cmd": ["bash"],
        "exposed_ports": {"8080/tcp": {}},
    }


@pytest.fixture
def mock_image_metadata_bad():
    """Bad image metadata — multiple issues expected."""
    return {
        "id": "sha256:def456",
        "tags": ["myapp:latest"],
        "size_mb": 980.0,
        "num_layers": 45,
        "base_image": "ubuntu:latest",
        "labels": {},
        "env_vars": ["SECRET_KEY=hardcoded", "DB_PASSWORD=letmein", "PATH=/usr/bin"],
        "user": "root",
        "architecture": "amd64",
        "os": "linux",
    }
