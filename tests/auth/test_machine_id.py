"""Unit tests for machine ID resolution and platform detection."""

from unittest.mock import MagicMock, mock_open, patch
import subprocess

import pytest

from safety.auth.constants import MACHINE_ID_MAX_LENGTH
from safety.auth.machine_id import (
    _validate_machine_id,
    resolve_machine_id,
)
from safety.errors import MachineIdUnavailableError
from safety.utils.machine_id import (
    get_linux_machine_id,
    get_macos_machine_id,
    get_windows_machine_id,
)


# ---------------------------------------------------------------------------
# _validate_machine_id
# ---------------------------------------------------------------------------


class TestValidateMachineId:
    """Tests for the _validate_machine_id helper."""

    @pytest.mark.unit
    def test_none_returns_none(self) -> None:
        assert _validate_machine_id(None) is None

    @pytest.mark.unit
    def test_empty_string_returns_none(self) -> None:
        assert _validate_machine_id("") is None

    @pytest.mark.unit
    def test_whitespace_only_returns_none(self) -> None:
        assert _validate_machine_id("   \t\n  ") is None

    @pytest.mark.unit
    def test_oversized_returns_none(self) -> None:
        assert _validate_machine_id("a" * (MACHINE_ID_MAX_LENGTH + 1)) is None

    @pytest.mark.unit
    def test_valid_value_returned(self) -> None:
        assert _validate_machine_id("abc-123") == "abc-123"

    @pytest.mark.unit
    def test_strips_whitespace(self) -> None:
        assert _validate_machine_id("  abc-123  ") == "abc-123"

    @pytest.mark.unit
    def test_max_length_value_accepted(self) -> None:
        value = "x" * MACHINE_ID_MAX_LENGTH
        assert _validate_machine_id(value) == value


# ---------------------------------------------------------------------------
# resolve_machine_id — override parameter
# ---------------------------------------------------------------------------


class TestResolveMachineIdOverride:
    """Tests for the override (highest priority) parameter."""

    @pytest.mark.unit
    def test_override_takes_highest_priority(self) -> None:
        """override is returned even when env var and enrolled value exist."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "env-id"}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=MagicMock(machine_id="enrolled-id"),
            ),
        ):
            result = resolve_machine_id(override="override-id")
            assert result == "override-id"

    @pytest.mark.unit
    def test_override_strips_whitespace(self) -> None:
        assert resolve_machine_id(override="  my-id  ") == "my-id"

    @pytest.mark.unit
    def test_override_empty_string_raises(self) -> None:
        with pytest.raises(MachineIdUnavailableError):
            resolve_machine_id(override="")

    @pytest.mark.unit
    def test_override_whitespace_only_raises(self) -> None:
        with pytest.raises(MachineIdUnavailableError):
            resolve_machine_id(override="   ")

    @pytest.mark.unit
    def test_override_oversized_raises(self) -> None:
        with pytest.raises(MachineIdUnavailableError):
            resolve_machine_id(override="x" * (MACHINE_ID_MAX_LENGTH + 1))


# ---------------------------------------------------------------------------
# resolve_machine_id — enrolled value
# ---------------------------------------------------------------------------


class TestResolveMachineIdEnrolled:
    """Tests for enrolled value from persistent storage."""

    @pytest.mark.unit
    def test_enrolled_value_used_when_skip_enrolled_false(self) -> None:
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=MagicMock(machine_id="enrolled-id"),
            ),
        ):
            result = resolve_machine_id(skip_enrolled=False)
            assert result == "enrolled-id"

    @pytest.mark.unit
    def test_enrolled_value_priority_over_env_var(self) -> None:
        """Enrolled value should take priority over the env var."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "env-id"}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=MagicMock(machine_id="enrolled-id"),
            ),
        ):
            result = resolve_machine_id(skip_enrolled=False)
            assert result == "enrolled-id"

    @pytest.mark.unit
    def test_skip_enrolled_true_bypasses_stored_value(self) -> None:
        """When skip_enrolled=True, the enrolled value is ignored."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "env-id"}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
            ) as mock_storage,
        ):
            result = resolve_machine_id(skip_enrolled=True)
            mock_storage.assert_not_called()
            assert result == "env-id"

    @pytest.mark.unit
    def test_enrolled_storage_exception_falls_through(self) -> None:
        """If reading storage raises, fall through to env var."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "env-id"}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                side_effect=OSError("corrupt file"),
            ),
        ):
            result = resolve_machine_id(skip_enrolled=False)
            assert result == "env-id"


# ---------------------------------------------------------------------------
# resolve_machine_id — environment variable
# ---------------------------------------------------------------------------


class TestResolveMachineIdEnvVar:
    """Tests for SAFETY_MACHINE_ID env var fallback."""

    @pytest.mark.unit
    def test_env_var_used_when_no_override_and_no_enrolled(self) -> None:
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "env-id"}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
        ):
            result = resolve_machine_id(skip_enrolled=False)
            assert result == "env-id"

    @pytest.mark.unit
    def test_env_var_strips_whitespace(self) -> None:
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "  env-id  "}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
        ):
            result = resolve_machine_id(skip_enrolled=False)
            assert result == "env-id"


# ---------------------------------------------------------------------------
# resolve_machine_id — all sources fail
# ---------------------------------------------------------------------------


class TestResolveMachineIdAllFail:
    """Tests for the case where no source yields a valid ID."""

    @pytest.mark.unit
    def test_raises_when_all_sources_fail(self) -> None:
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Linux"),
            patch("safety.auth.machine_id.get_linux_machine_id", return_value=None),
        ):
            with pytest.raises(MachineIdUnavailableError):
                resolve_machine_id()

    @pytest.mark.unit
    def test_raises_on_unknown_platform(self) -> None:
        """Unknown platform has no detector, so it raises."""
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="FreeBSD"),
        ):
            with pytest.raises(MachineIdUnavailableError):
                resolve_machine_id()


# ---------------------------------------------------------------------------
# Platform detection — Linux
# ---------------------------------------------------------------------------


class TestGetLinuxMachineId:
    """Tests for get_linux_machine_id()."""

    @pytest.mark.unit
    def test_reads_etc_machine_id(self) -> None:
        fake_stat = MagicMock()
        fake_stat.st_size = 33
        fake_stat.st_mode = 0o100644  # regular file

        with (
            patch("safety.utils.machine_id.os.stat", return_value=fake_stat),
            patch("builtins.open", mock_open(read_data="abc123\n")),
        ):
            result = get_linux_machine_id()
            assert result == "abc123"

    @pytest.mark.unit
    def test_fallback_to_dbus_machine_id(self) -> None:
        """When /etc/machine-id fails, falls back to /var/lib/dbus/machine-id."""
        fake_stat = MagicMock()
        fake_stat.st_size = 33
        fake_stat.st_mode = 0o100644

        call_count = 0

        def stat_side_effect(path: str) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if path == "/etc/machine-id":
                raise OSError("not found")
            return fake_stat

        with (
            patch("safety.utils.machine_id.os.stat", side_effect=stat_side_effect),
            patch("builtins.open", mock_open(read_data="dbus-id\n")),
        ):
            result = get_linux_machine_id()
            assert result == "dbus-id"

    @pytest.mark.unit
    def test_both_paths_fail_returns_none(self) -> None:
        with patch("safety.utils.machine_id.os.stat", side_effect=OSError("not found")):
            result = get_linux_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_oversized_file_skipped(self) -> None:
        """Files larger than 64 bytes are skipped."""
        fake_stat = MagicMock()
        fake_stat.st_size = 100  # > 64 max
        fake_stat.st_mode = 0o100644

        with patch("safety.utils.machine_id.os.stat", return_value=fake_stat):
            result = get_linux_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_empty_file_skipped(self) -> None:
        fake_stat = MagicMock()
        fake_stat.st_size = 1
        fake_stat.st_mode = 0o100644

        with (
            patch("safety.utils.machine_id.os.stat", return_value=fake_stat),
            patch("builtins.open", mock_open(read_data="  \n")),
        ):
            # Both paths return whitespace-only — should return None
            result = get_linux_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_non_regular_file_skipped(self) -> None:
        """Directories and symlinks are skipped (S_ISREG check)."""
        fake_stat = MagicMock()
        fake_stat.st_size = 33
        fake_stat.st_mode = 0o040755  # directory, not regular file

        with patch("safety.utils.machine_id.os.stat", return_value=fake_stat):
            result = get_linux_machine_id()
            assert result is None


# ---------------------------------------------------------------------------
# Platform detection — macOS
# ---------------------------------------------------------------------------


class TestGetMacosMachineId:
    """Tests for get_macos_machine_id()."""

    IOREG_OUTPUT = """\
+-o Root  <class IORegistryEntry, id 0x100000100, retain 11>
  +-o MacBookPro  <class IOPlatformExpertDevice>
    | "IOPlatformUUID" = "12345678-ABCD-1234-EFGH-123456789ABC"
    | "board-id" = <"Mac-xyz">
"""

    @pytest.mark.unit
    def test_parses_ioreg_output(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=self.IOREG_OUTPUT, stderr=""
        )
        with patch("safety.utils.machine_id.subprocess.run", return_value=completed):
            result = get_macos_machine_id()
            assert result == "12345678-ABCD-1234-EFGH-123456789ABC"

    @pytest.mark.unit
    def test_nonzero_returncode_returns_none(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        with patch("safety.utils.machine_id.subprocess.run", return_value=completed):
            result = get_macos_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_timeout_returns_none(self) -> None:
        with patch(
            "safety.utils.machine_id.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ioreg", timeout=5),
        ):
            result = get_macos_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_file_not_found_returns_none(self) -> None:
        with patch(
            "safety.utils.machine_id.subprocess.run",
            side_effect=FileNotFoundError("ioreg not found"),
        ):
            result = get_macos_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_no_uuid_in_output_returns_none(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="some output without uuid\n", stderr=""
        )
        with patch("safety.utils.machine_id.subprocess.run", return_value=completed):
            result = get_macos_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_oserror_returns_none(self) -> None:
        """Generic OSError (e.g. PermissionError) is caught."""
        with patch(
            "safety.utils.machine_id.subprocess.run",
            side_effect=PermissionError("permission denied"),
        ):
            result = get_macos_machine_id()
            assert result is None


# ---------------------------------------------------------------------------
# Platform detection — Windows
# ---------------------------------------------------------------------------


class TestGetWindowsMachineId:
    """Tests for get_windows_machine_id()."""

    @pytest.mark.unit
    def test_reads_registry_guid(self) -> None:
        mock_key = MagicMock()
        with patch("safety.utils.machine_id.winreg", create=True) as mock_winreg:
            mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
            mock_winreg.REG_SZ = 1
            mock_winreg.OpenKey.return_value.__enter__ = MagicMock(
                return_value=mock_key
            )
            mock_winreg.OpenKey.return_value.__exit__ = MagicMock(return_value=False)
            mock_winreg.QueryValueEx.return_value = (
                "AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF",
                1,  # REG_SZ
            )
            result = get_windows_machine_id()
            assert result == "AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF"

            mock_winreg.OpenKey.assert_called_once_with(
                0x80000002, r"SOFTWARE\Microsoft\Cryptography"
            )

    @pytest.mark.unit
    def test_registry_oserror_returns_none(self) -> None:
        with patch("safety.utils.machine_id.winreg", create=True) as mock_winreg:
            mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
            mock_winreg.OpenKey.side_effect = OSError("access denied")
            result = get_windows_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_wrong_registry_type_returns_none(self) -> None:
        mock_key = MagicMock()
        with patch("safety.utils.machine_id.winreg", create=True) as mock_winreg:
            mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
            mock_winreg.REG_SZ = 1
            mock_winreg.OpenKey.return_value.__enter__ = MagicMock(
                return_value=mock_key
            )
            mock_winreg.OpenKey.return_value.__exit__ = MagicMock(return_value=False)
            mock_winreg.QueryValueEx.return_value = (
                123,
                3,  # REG_BINARY, not REG_SZ
            )
            result = get_windows_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_empty_string_value_returns_none(self) -> None:
        """REG_SZ with empty string should return None."""
        mock_key = MagicMock()
        with patch("safety.utils.machine_id.winreg", create=True) as mock_winreg:
            mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
            mock_winreg.REG_SZ = 1
            mock_winreg.OpenKey.return_value.__enter__ = MagicMock(
                return_value=mock_key
            )
            mock_winreg.OpenKey.return_value.__exit__ = MagicMock(return_value=False)
            mock_winreg.QueryValueEx.return_value = ("", 1)  # empty REG_SZ
            result = get_windows_machine_id()
            assert result is None

    @pytest.mark.unit
    def test_registry_type_error_returns_none(self) -> None:
        """TypeError from registry operations is caught."""
        with patch("safety.utils.machine_id.winreg", create=True) as mock_winreg:
            mock_winreg.HKEY_LOCAL_MACHINE = 0x80000002
            mock_winreg.OpenKey.side_effect = TypeError("unexpected type")
            result = get_windows_machine_id()
            assert result is None


# ---------------------------------------------------------------------------
# resolve_machine_id — invalid value fallthrough edge cases
# ---------------------------------------------------------------------------


class TestResolveMachineIdInvalidFallthrough:
    """Tests for invalid values falling through to the next resolution layer."""

    @pytest.mark.unit
    def test_enrolled_empty_machine_id_falls_through_to_env_var(self) -> None:
        """Storage returns config with empty machine_id; should use env var."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "env-id"}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=MagicMock(machine_id=""),
            ),
        ):
            assert resolve_machine_id(skip_enrolled=False) == "env-id"

    @pytest.mark.unit
    def test_enrolled_oversized_machine_id_falls_through_to_env_var(self) -> None:
        """Storage returns config with oversized machine_id; should use env var."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "env-id"}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=MagicMock(machine_id="x" * (MACHINE_ID_MAX_LENGTH + 1)),
            ),
        ):
            assert resolve_machine_id(skip_enrolled=False) == "env-id"

    @pytest.mark.unit
    def test_enrolled_none_machine_id_falls_through_to_env_var(self) -> None:
        """Storage returns config with machine_id=None; should use env var."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "env-id"}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=MagicMock(machine_id=None),
            ),
        ):
            assert resolve_machine_id(skip_enrolled=False) == "env-id"

    @pytest.mark.unit
    def test_env_var_empty_falls_through_to_platform(self) -> None:
        """SAFETY_MACHINE_ID="" should fall through to platform detection."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": ""}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Linux"),
            patch(
                "safety.auth.machine_id.get_linux_machine_id",
                return_value="linux-id",
            ),
        ):
            assert resolve_machine_id() == "linux-id"

    @pytest.mark.unit
    def test_env_var_whitespace_only_falls_through_to_platform(self) -> None:
        """SAFETY_MACHINE_ID="   " should fall through to platform detection."""
        with (
            patch.dict("os.environ", {"SAFETY_MACHINE_ID": "   \t  "}),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Linux"),
            patch(
                "safety.auth.machine_id.get_linux_machine_id",
                return_value="linux-id",
            ),
        ):
            assert resolve_machine_id() == "linux-id"

    @pytest.mark.unit
    def test_env_var_oversized_falls_through_to_platform(self) -> None:
        """Oversized SAFETY_MACHINE_ID should fall through to platform."""
        with (
            patch.dict(
                "os.environ",
                {"SAFETY_MACHINE_ID": "x" * (MACHINE_ID_MAX_LENGTH + 1)},
            ),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Linux"),
            patch(
                "safety.auth.machine_id.get_linux_machine_id",
                return_value="linux-id",
            ),
        ):
            assert resolve_machine_id() == "linux-id"

    @pytest.mark.unit
    def test_platform_detector_invalid_value_raises(self) -> None:
        """Platform detector returns value failing validation; should raise."""
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Linux"),
            patch(
                "safety.auth.machine_id.get_linux_machine_id",
                return_value="   ",  # whitespace-only fails validation
            ),
        ):
            with pytest.raises(MachineIdUnavailableError):
                resolve_machine_id()


# ---------------------------------------------------------------------------
# resolve_machine_id — platform dispatch integration
# ---------------------------------------------------------------------------


class TestResolveMachineIdPlatformDispatch:
    """Tests for platform detection dispatch within resolve_machine_id."""

    @pytest.mark.unit
    def test_linux_detector_called(self) -> None:
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Linux"),
            patch(
                "safety.auth.machine_id.get_linux_machine_id",
                return_value="linux-id",
            ),
        ):
            assert resolve_machine_id() == "linux-id"

    @pytest.mark.unit
    def test_darwin_detector_called(self) -> None:
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Darwin"),
            patch(
                "safety.auth.machine_id.get_macos_machine_id",
                return_value="macos-id",
            ),
        ):
            assert resolve_machine_id() == "macos-id"

    @pytest.mark.unit
    def test_windows_detector_called(self) -> None:
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Windows"),
            patch(
                "safety.auth.machine_id.get_windows_machine_id",
                return_value="windows-id",
            ),
        ):
            assert resolve_machine_id() == "windows-id"

    @pytest.mark.unit
    def test_platform_detector_exception_raises(self) -> None:
        """If the platform detector raises, resolve_machine_id raises."""
        with (
            patch.dict("os.environ", {}, clear=True),
            patch(
                "safety.auth.machine_id.MachineCredentialConfig.from_storage",
                return_value=None,
            ),
            patch("safety.auth.machine_id.platform.system", return_value="Linux"),
            patch(
                "safety.auth.machine_id.get_linux_machine_id",
                side_effect=OSError("hw error"),
            ),
        ):
            with pytest.raises(MachineIdUnavailableError):
                resolve_machine_id()
