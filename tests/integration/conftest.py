"""
Integration test harness for testing Safety CLI commands against real API servers.

Prerequisites:
    1. A running API server (local dev, beta, or staging)
    2. Environment variable SAFETY_PLATFORM_V2_URL set to the server URL
    3. Command-specific parameters (e.g., enrollment key for enroll tests)

Quick start -- local dev server:
    # Terminal 1: Start platform-v2 dev server
    cd ../platform-v2
    make platform-dev-server    # Runs on http://localhost:8000

    # Terminal 2: Run integration tests
    SAFETY_PLATFORM_V2_URL=http://localhost:8000 \\
      hatch run test tests/integration/test_enroll.py \\
      --enrollment-key sfek_...

Pointing at beta/staging:
    SAFETY_PLATFORM_V2_URL=https://beta.safetycli.com \\
      hatch run test tests/integration/test_enroll.py \\
      --enrollment-key sfek_...

Running all integration tests:
    SAFETY_PLATFORM_V2_URL=http://localhost:8000 \\
      hatch run test tests/integration/ --enrollment-key sfek_...

How it works:
    - Tests auto-skip if SAFETY_PLATFORM_V2_URL is unreachable (checks GET /health/)
    - Tests auto-skip if required command-specific options aren't provided
    - Auth storage is isolated to temp directories (no writes to ~/.safety/)
    - OAuth/JWKS network calls are bypassed (only the command-under-test hits the server)

Adding tests for a new command:
    1. Add any needed pytest options to conftest.py's pytest_addoption()
    2. Create tests/integration/test_<command>.py
    3. Use the shared fixtures: cli_runner, isolated_auth_storage, bypass_auth_session
    4. Mark all tests with @requires_platform and @pytest.mark.integration

Environment variable override:
    SAFETY_PLATFORM_V2_URL -- Platform v2 base URL (default: https://service.platformv2.safetycli.com)

    Currently only SAFETY_PLATFORM_V2_URL is overridable at test time via
    monkeypatch.setenv(). This works because enrollment.py resolves the URL
    at call time via get_required_config_setting().

    Other settings (PLATFORM_API_BASE_URL, DATA_API_BASE_URL, AUTH_SERVER_URL,
    CLIENT_ID, FIREWALL_API_BASE_URL) are resolved at module import time in
    safety/constants.py and safety/auth/constants.py, so monkeypatch.setenv()
    has no effect on them. To add integration tests for commands that use those
    settings (scan, firewall, etc.), their consumers need to be refactored from
    module-level constants to call-time resolution -- same pattern used in
    enrollment.py.
"""

import os
from unittest.mock import patch

import httpx
import pytest
from click.testing import CliRunner
from importlib.metadata import version
from packaging.version import Version

from safety.cli import cli


# ---------------------------------------------------------------------------
# pytest options -- add command-specific options here
# ---------------------------------------------------------------------------


def pytest_addoption(parser):
    parser.addoption(
        "--enrollment-key",
        action="store",
        default=None,
        help="Enrollment key for MDM enrollment integration tests",
    )
    # Future commands add their options here


# ---------------------------------------------------------------------------
# Server health check
# ---------------------------------------------------------------------------

LOCAL_API_URL = os.environ.get("SAFETY_PLATFORM_V2_URL", "http://localhost:8000")


def _is_server_running():
    try:
        return httpx.get(f"{LOCAL_API_URL}/health/", timeout=2.0).status_code == 200
    except (httpx.HTTPError, OSError):
        return False


requires_platform = pytest.mark.skipif(
    not _is_server_running(),
    reason=f"Platform API not reachable at {LOCAL_API_URL}",
)


# ---------------------------------------------------------------------------
# Isolated auth storage -- prevents writes to real ~/.safety/
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_auth_storage(tmp_path, monkeypatch):
    """Redirect auth credential storage to a temp directory."""
    auth_ini = tmp_path / ".safety" / "auth.ini"
    auth_ini.parent.mkdir(parents=True)
    monkeypatch.setattr("safety.config.auth.AUTH_CONFIG_USER", auth_ini)
    return auth_ini


# ---------------------------------------------------------------------------
# CLI runner
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_runner():
    """Return a (CliRunner, cli) pair ready for ``runner.invoke(cli, ...)``."""
    if Version(version("click")) >= Version("8.2.0"):
        runner = CliRunner()
    else:
        runner = CliRunner(mix_stderr=False)
    cli.commands = cli.all_commands
    return runner, cli


# ---------------------------------------------------------------------------
# Auth session bypass -- skip OAuth/JWKS calls during CLI init
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def bypass_auth_session():
    """Prevent network calls to the auth server during CLI bootstrap."""
    with patch("safety.cli_util.configure_auth_session"):
        yield
