import pytest
from unittest.mock import Mock
from pathlib import Path
from typing import Generator
import tempfile

from safety.system_scan.scanner.context import Config, DetectContext
from safety.system_scan.scanner.filesystem import FsRuntime
from safety.system_scan.scanner.callbacks import NullCallbacks
from safety.system_scan.scanner.registry import ScanRefRegistry
from safety.system_scan.scanner.events.payloads.links import (
    ExecutionContextRelation,
    HostRef,
)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """
    Temporary directory for test files.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def minimal_config() -> Config:
    """
    Minimal configuration for testing.
    """
    return Config(max_depth=2, prune_dirs=[".git", "__pycache__"])


@pytest.fixture
def mock_fs_runtime() -> Mock:
    """
    Mock filesystem runtime.
    """
    return Mock(spec=FsRuntime)


@pytest.fixture
def mock_callbacks() -> Mock:
    """
    Mock callbacks interface.
    """
    return Mock(spec=NullCallbacks)


@pytest.fixture
def mock_registry() -> Mock:
    """
    Mock scan reference registry.
    """
    return Mock(spec=ScanRefRegistry)


@pytest.fixture
def mock_exec_ctx_rel() -> ExecutionContextRelation:
    """
    Mock execution context relation.
    """
    return ExecutionContextRelation(
        ref=HostRef(machine_id="test-machine", hostname="test-host")
    )


@pytest.fixture
def detect_context(
    mock_exec_ctx_rel: ExecutionContextRelation,
    mock_registry: Mock,
    mock_callbacks: Mock,
    minimal_config: Config,
    mock_fs_runtime: Mock,
) -> DetectContext:
    """
    Complete detection context for testing.
    """
    return DetectContext(
        exec_ctx_rel=mock_exec_ctx_rel,
        registry=mock_registry,
        callbacks=mock_callbacks,
        config=minimal_config,
        fs=mock_fs_runtime,
    )


@pytest.fixture
def sample_site_packages(temp_dir: Path) -> Path:
    """
    Sample site-packages directory structure.
    """
    site_packages = temp_dir / "lib" / "python3.9" / "site-packages"
    site_packages.mkdir(parents=True)

    # Create sample dist-info directories
    (site_packages / "requests-2.28.0.dist-info").mkdir()
    (site_packages / "Django-4.1.0.dist-info").mkdir()

    # Create sample egg-info directories
    (site_packages / "old_package-1.0.egg-info").mkdir()

    return site_packages


@pytest.fixture
def mock_http_client() -> Mock:
    """
    Mock HTTP client for streaming tests.
    """
    return Mock()
