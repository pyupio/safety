import pytest
from typing import List, Tuple, Generator
from unittest.mock import Mock, MagicMock, patch
from pathlib import Path

from safety.tool.interceptors.windows import AutoRunManager


@pytest.fixture(scope="module", autouse=True)
def ensure_winreg_mockable():
    """
    Ensure winreg can be mocked on all platforms by making it available
    as an attribute on the windows module if it doesn't exist.
    """
    from safety.tool.interceptors import windows

    # If winreg doesn't exist as an attribute, create a placeholder
    if not hasattr(windows, "winreg"):
        windows.winreg = None

    yield

    # Clean up if we added it
    if hasattr(windows, "winreg") and windows.winreg is None:
        delattr(windows, "winreg")


TOKENIZER_TEST_CASES = [
    # Basic cases
    ("", []),
    ("doskey.exe", ["doskey.exe"]),
    ("cmd1 & cmd2", ["cmd1 ", "&", " cmd2"]),
    ("cmd1&&cmd2", ["cmd1", "&&", "cmd2"]),
    ("cmd1 || cmd2", ["cmd1 ", "||", " cmd2"]),
    (
        "cmd1 & cmd2 && cmd3 | cmd4 || cmd5",
        ["cmd1 ", "&", " cmd2 ", "&&", " cmd3 ", "|", " cmd4 ", "||", " cmd5"],
    ),
    # Quoted strings
    (
        '"C:\\Program Files\\Tool\\app.exe" && script.bat',
        ['"C:\\Program Files\\Tool\\app.exe" ', "&&", " script.bat"],
    ),
    # Whitespace variations
    ("cmd1&&cmd2||cmd3", ["cmd1", "&&", "cmd2", "||", "cmd3"]),
    ("cmd1  &  cmd2", ["cmd1  ", "&", "  cmd2"]),
    ("  cmd1 & cmd2  ", ["  cmd1 ", "&", " cmd2  "]),
    # Doskey scenarios
    ("doskey ls=dir $*", ["doskey ls=dir $*"]),
    (
        'doskey /macrofile="C:\\aliases.txt" && echo Loaded',
        ['doskey /macrofile="C:\\aliases.txt" ', "&&", " echo Loaded"],
    ),
    # Corporate scenarios
    (
        '"C:\\McAfee\\agent.exe" --background && "C:\\Scripts\\init.bat"',
        ['"C:\\McAfee\\agent.exe" --background ', "&&", ' "C:\\Scripts\\init.bat"'],
    ),
    (
        "antivirus.exe /silent && logger.exe --start && cleanup.bat",
        ["antivirus.exe /silent ", "&&", " logger.exe --start ", "&&", " cleanup.bat"],
    ),
    # Environment variables
    (
        '"%USERPROFILE%\\Scripts\\startup.bat"',
        ['"%USERPROFILE%\\Scripts\\startup.bat"'],
    ),
    (
        '"%ProgramFiles%\\Tool\\app.exe" && script.bat',
        ['"%ProgramFiles%\\Tool\\app.exe" ', "&&", " script.bat"],
    ),
    # Edge cases
    ("& script.bat", ["&", " script.bat"]),
    ("script.bat &", ["script.bat ", "&"]),
    ("&", ["&"]),
    ("&&", ["&&"]),
    # Path variations
    (
        "C:\\PROGRA~1\\Tool\\app.exe && script.bat",
        ["C:\\PROGRA~1\\Tool\\app.exe ", "&&", " script.bat"],
    ),
    (
        '"C:/Scripts/startup.bat" && echo Done',
        ['"C:/Scripts/startup.bat" ', "&&", " echo Done"],
    ),
    # Parameters
    (
        "tool.exe /silent && script.bat --verbose",
        ["tool.exe /silent ", "&&", " script.bat --verbose"],
    ),
    (
        'app.exe --config="C:\\config.ini" && next.bat',
        ['app.exe --config="C:\\config.ini" ', "&&", " next.bat"],
    ),
    # Complex realistic scenarios
    (
        '"C:\\Company\\Security\\endpoint.exe" --silent && "C:\\Scripts\\inventory.bat" && echo Done',
        [
            '"C:\\Company\\Security\\endpoint.exe" --silent ',
            "&&",
            ' "C:\\Scripts\\inventory.bat" ',
            "&&",
            " echo Done",
        ],
    ),
]


@pytest.mark.unit
class TestAutoRunManagerLogicMethods:
    """
    Test pure logic methods that don't touch registry
    """

    @pytest.mark.parametrize("input_val,expected", TOKENIZER_TEST_CASES)
    def test_tokenize_autorun_scenarios(
        self, input_val: str, expected: List[str]
    ) -> None:
        manager = AutoRunManager()
        result = manager._tokenize_autorun(input_val)
        assert result == expected

    @pytest.mark.parametrize(
        "separator,expected",
        [
            ("&", True),
            ("&&", True),
            ("|", True),
            ("||", True),
            ("  &  ", True),
            ("command", False),
            ("", False),
            ("cmd&script", False),
        ],
    )
    def test_separator_detection(self, separator: str, expected: bool) -> None:
        manager = AutoRunManager()
        result = manager._is_separator(separator)
        assert result == expected

    def test_script_existence_detection(self) -> None:
        manager = AutoRunManager()
        tokens = ["script1.bat", " & ", "script2.bat", "  script3.bat  "]

        assert manager._script_exists_in_tokens(tokens, "script1.bat")
        assert manager._script_exists_in_tokens(
            tokens, "script3.bat"
        )  # whitespace ignored
        assert not manager._script_exists_in_tokens(tokens, "nonexistent.bat")
        assert not manager._script_exists_in_tokens([], "any_script.bat")

    def test_script_token_removal(self) -> None:
        manager = AutoRunManager()

        tokens = ["script1.bat", " & ", "script2.bat"]
        result = manager._remove_script_tokens(tokens, "script1.bat")
        assert result == ["script2.bat"]

        tokens = ["script1.bat", "script2.bat"]
        result = manager._remove_script_tokens(tokens, "script1.bat")
        assert result == ["script2.bat"]

        tokens = ["cmd1", " & ", "script.bat", " && ", "cmd2"]
        result = manager._remove_script_tokens(tokens, "script.bat")
        assert result == ["cmd1", "&", "cmd2"]

        tokens = ["script1.bat", "&", "script2.bat"]
        result = manager._remove_script_tokens(tokens, "nonexistent.bat")
        assert result == tokens


@pytest.mark.unit
class TestAutoRunManagerRegistryOperations:
    """
    Test AutoRun registry operations with mocked winreg
    """

    @pytest.fixture
    def mock_winreg(self) -> Generator[Tuple[Mock, Mock], None, None]:
        """
        Fixture providing mocked winreg module and key
        """
        with patch("safety.tool.interceptors.windows.winreg") as mock_reg:
            mock_key = MagicMock()
            mock_reg.OpenKey.return_value.__enter__.return_value = mock_key
            mock_reg.CreateKey.return_value.__enter__.return_value = mock_key
            mock_reg.HKEY_CURRENT_USER = "HKEY_CURRENT_USER"
            mock_reg.KEY_READ = 1
            mock_reg.KEY_SET_VALUE = 2
            mock_reg.REG_SZ = 1
            yield mock_reg, mock_key

    def test_registry_key_operations(self, mock_winreg: Tuple[Mock, Mock]) -> None:
        """Test registry key opening and creation"""
        mock_reg, mock_key = mock_winreg
        manager = AutoRunManager()

        # Test successful key opening
        with manager._open_registry_key() as key:
            assert key == mock_key
        mock_reg.OpenKey.assert_called_once()

        # Test key creation when not found
        mock_reg.OpenKey.side_effect = FileNotFoundError()
        mock_reg.reset_mock()

        with manager._open_registry_key() as key:
            assert key == mock_key
        mock_reg.CreateKey.assert_called_once()

    def test_get_current_tokens_operations(
        self, mock_winreg: Tuple[Mock, Mock]
    ) -> None:
        """Test getting current tokens from registry"""
        mock_reg, mock_key = mock_winreg
        manager = AutoRunManager()

        # Test with existing value
        mock_reg.QueryValueEx.return_value = ("cmd1 & cmd2", mock_reg.REG_SZ)
        result = manager._get_current_tokens(mock_key)
        assert result == ["cmd1 ", "&", " cmd2"]

        # Test with missing value
        mock_reg.QueryValueEx.side_effect = FileNotFoundError()
        result = manager._get_current_tokens(mock_key)
        assert result == []

    def test_registry_value_modification(self, mock_winreg: Tuple[Mock, Mock]) -> None:
        """Test setting and deleting registry values"""
        mock_reg, mock_key = mock_winreg
        manager = AutoRunManager()

        # Test setting value
        test_value = "test_script.bat & other_cmd"
        manager._set_autorun_value(mock_key, test_value)
        mock_reg.SetValueEx.assert_called_once_with(
            mock_key, "AutoRun", 0, mock_reg.REG_SZ, test_value
        )

        # Test deleting value
        manager._delete_autorun_value(mock_key)
        mock_reg.DeleteValue.assert_called_once_with(mock_key, "AutoRun")


@pytest.mark.unit
class TestAutoRunManagerPublicAPI:
    """
    Test the public API methods (add_script, remove_script, get_current_commands)
    """

    @pytest.fixture
    def mock_winreg(self) -> Generator[Tuple[Mock, Mock], None, None]:
        """Fixture for public API tests"""
        with patch("safety.tool.interceptors.windows.winreg") as mock_reg:
            mock_key = MagicMock()
            mock_reg.OpenKey.return_value.__enter__.return_value = mock_key
            mock_reg.REG_SZ = 1
            yield mock_reg, mock_key

    def test_add_script_scenarios(self, mock_winreg: Tuple[Mock, Mock]) -> None:
        mock_reg, mock_key = mock_winreg
        manager = AutoRunManager()

        # Test adding to empty AutoRun
        mock_reg.QueryValueEx.side_effect = FileNotFoundError()
        result = manager.add_script("test_script.bat")
        assert result is True
        mock_reg.SetValueEx.assert_called_with(
            mock_key, "AutoRun", 0, mock_reg.REG_SZ, "test_script.bat"
        )

        # Test adding to existing AutoRun
        mock_reg.reset_mock()
        mock_reg.QueryValueEx.side_effect = None
        mock_reg.QueryValueEx.return_value = ("existing_cmd", mock_reg.REG_SZ)
        result = manager.add_script("new_script.bat")
        assert result is True
        mock_reg.SetValueEx.assert_called_with(
            mock_key, "AutoRun", 0, mock_reg.REG_SZ, "new_script.bat & existing_cmd"
        )

        # Test adding duplicate (should not modify)
        mock_reg.reset_mock()
        mock_reg.QueryValueEx.return_value = (
            "existing_cmd & test_script.bat",
            mock_reg.REG_SZ,
        )
        result = manager.add_script("test_script.bat")
        assert result is True
        mock_reg.SetValueEx.assert_not_called()

        # Test Path object conversion
        mock_reg.reset_mock()
        mock_reg.QueryValueEx.side_effect = FileNotFoundError()
        script_path = Path("C:\\test\\script.bat")
        result = manager.add_script(script_path)
        assert result is True
        mock_reg.SetValueEx.assert_called_with(
            mock_key, "AutoRun", 0, mock_reg.REG_SZ, str(script_path)
        )

    def test_remove_script_scenarios(self, mock_winreg: Tuple[Mock, Mock]) -> None:
        mock_reg, mock_key = mock_winreg
        manager = AutoRunManager()

        # Test removing from multiple commands
        mock_reg.QueryValueEx.return_value = (
            "test_script.bat & other_cmd",
            mock_reg.REG_SZ,
        )
        result = manager.remove_script("test_script.bat")
        assert result is True
        mock_reg.SetValueEx.assert_called_with(
            mock_key, "AutoRun", 0, mock_reg.REG_SZ, "other_cmd"
        )

        # Test removing only command (should delete value)
        mock_reg.reset_mock()
        mock_reg.QueryValueEx.return_value = ("test_script.bat", mock_reg.REG_SZ)
        result = manager.remove_script("test_script.bat")
        assert result is True
        mock_reg.DeleteValue.assert_called_once_with(mock_key, "AutoRun")
        mock_reg.SetValueEx.assert_not_called()

        # Test removing non-existent script
        mock_reg.reset_mock()
        mock_reg.QueryValueEx.return_value = ("other_cmd", mock_reg.REG_SZ)
        result = manager.remove_script("nonexistent.bat")
        assert result is True
        mock_reg.SetValueEx.assert_not_called()
        mock_reg.DeleteValue.assert_not_called()

    def test_get_current_commands_scenarios(
        self, mock_winreg: Tuple[Mock, Mock]
    ) -> None:
        mock_reg, mock_key = mock_winreg
        manager = AutoRunManager()

        # Test with commands and separators
        autorun_value = "  cmd1.bat  & cmd2.exe && cmd3.bat  "
        mock_reg.QueryValueEx.return_value = (autorun_value, mock_reg.REG_SZ)
        result = manager.get_current_commands()
        assert result == ["cmd1.bat", "cmd2.exe", "cmd3.bat"]

        # Test with empty/whitespace tokens
        autorun_value = "cmd1.bat &  & cmd2.exe &   & cmd3.bat"
        mock_reg.QueryValueEx.return_value = (autorun_value, mock_reg.REG_SZ)
        result = manager.get_current_commands()
        assert result == ["cmd1.bat", "cmd2.exe", "cmd3.bat"]

        # Test with no AutoRun value
        mock_reg.QueryValueEx.side_effect = FileNotFoundError()
        result = manager.get_current_commands()
        assert result == []

    def test_error_handling(self, mock_winreg: Tuple[Mock, Mock]) -> None:
        mock_reg, mock_key = mock_winreg
        manager = AutoRunManager()

        # Test add_script error handling
        mock_reg.OpenKey.side_effect = Exception("Registry error")
        result = manager.add_script("test.bat")
        assert result is False

        # Test remove_script error handling
        result = manager.remove_script("test.bat")
        assert result is False

        # Test get_current_commands error handling
        result = manager.get_current_commands()
        assert result == []


@pytest.mark.unit
class TestAutoRunManagerEdgeCases:
    def test_edge_cases_and_defensive_programming(self) -> None:
        manager = AutoRunManager()

        # Test with empty script path
        tokens = ["script.bat", " & ", "other.bat"]
        expected_tokens = [token.strip() for token in tokens]

        assert not manager._script_exists_in_tokens(tokens, "")
        assert manager._remove_script_tokens(tokens, "") == expected_tokens

        assert manager._tokenize_autorun(None) == []  # type: ignore

        with pytest.raises(AttributeError):
            manager._is_separator(None)  # type: ignore
