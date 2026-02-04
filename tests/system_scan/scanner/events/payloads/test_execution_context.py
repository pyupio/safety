import pytest
from safety.system_scan.scanner.events.payloads.execution_context import (
    HostExecutionContext,
    WslExecutionContext,
    OsFamily,
    ExecutionContextSubtype,
)


def test_host_execution_context_requires_os_username():
    with pytest.raises(TypeError, match="Missing required argument: os_username"):
        HostExecutionContext(
            arch="x86_64",
            kernel_name="Linux",
            kernel_version="5.15.0",
            os_name="Ubuntu",
            os_family=OsFamily.LINUX,
            os_version="22.04",
            hostname="test-host",
        )


def test_host_execution_context_requires_machine_id():
    with pytest.raises(TypeError, match="Missing required argument: machine_id"):
        HostExecutionContext(
            arch="x86_64",
            kernel_name="Linux",
            kernel_version="5.15.0",
            os_name="Ubuntu",
            os_family=OsFamily.LINUX,
            os_version="22.04",
            os_username="testuser",
            hostname="test-host",
        )


def test_host_execution_context_creation_with_required_fields():
    context = HostExecutionContext(
        arch="x86_64",
        kernel_name="Linux",
        kernel_version="5.15.0",
        os_name="Ubuntu",
        os_family=OsFamily.LINUX,
        os_version="22.04",
        machine_id="test-machine-123",
        os_username="testuser",
        hostname="test-host",
    )

    assert context.machine_id == "test-machine-123"
    assert context.os_username == "testuser"
    assert context.subtype == ExecutionContextSubtype.HOST


def test_wsl_execution_context_requires_os_username():
    with pytest.raises(TypeError, match="Missing required argument: os_username"):
        WslExecutionContext(
            arch="x86_64",
            kernel_name="Linux",
            kernel_version="5.15.0",
            os_name="Ubuntu",
            os_family=OsFamily.LINUX,
            os_version="22.04",
            hostname="test-wsl-host",
        )


def test_wsl_execution_context_requires_machine_id():
    with pytest.raises(TypeError, match="Missing required argument: machine_id"):
        WslExecutionContext(
            arch="x86_64",
            kernel_name="Linux",
            kernel_version="5.15.0",
            os_name="Ubuntu",
            os_family=OsFamily.LINUX,
            os_version="22.04",
            os_username="wsluser",
            hostname="test-wsl-host",
        )


def test_wsl_execution_context_creation_with_required_fields():
    context = WslExecutionContext(
        arch="x86_64",
        kernel_name="Linux",
        kernel_version="5.15.0",
        os_name="Ubuntu",
        os_family=OsFamily.LINUX,
        os_version="22.04",
        machine_id="test-wsl-machine",
        os_username="wsluser",
        hostname="test-wsl-host",
    )

    assert context.machine_id == "test-wsl-machine"
    assert context.os_username == "wsluser"
    assert context.subtype == ExecutionContextSubtype.WSL


def test_execution_context_with_optional_fields():
    context = HostExecutionContext(
        arch="x86_64",
        kernel_name="Linux",
        kernel_version="5.15.0",
        os_name="Ubuntu",
        os_family=OsFamily.LINUX,
        os_version="22.04",
        machine_id="test-machine-123",
        os_username="testuser",
        hostname="test-host",
        os_build="22.04.3",
    )

    assert context.hostname == "test-host"
    assert context.os_build == "22.04.3"


def test_os_family_enum_values():
    assert OsFamily.WINDOWS.value == "windows"
    assert OsFamily.LINUX.value == "linux"
    assert OsFamily.MACOS.value == "macos"
    assert OsFamily.UNKNOWN.value == "unknown"


def test_execution_context_subtype_enum_values():
    assert ExecutionContextSubtype.HOST.value == "host"
    assert ExecutionContextSubtype.WSL.value == "wsl"


def test_execution_context_with_empty_strings():
    with pytest.raises(TypeError, match="Missing required argument: machine_id"):
        HostExecutionContext(
            arch="x86_64",
            kernel_name="Linux",
            kernel_version="5.15.0",
            os_name="Ubuntu",
            os_family=OsFamily.LINUX,
            os_version="22.04",
            os_username="",
            hostname="",
        )
