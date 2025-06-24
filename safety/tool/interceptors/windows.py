import logging
import os
import re
import shutil
from pathlib import Path
from sys import platform
from typing import TYPE_CHECKING, Dict, List

from .base import CommandInterceptor, Tool
from .types import InterceptorType

if TYPE_CHECKING or platform == "win32":
    import winreg

from typing import Union

logger = logging.getLogger(__name__)


class AutoRunManager:
    """
    Manages Windows Command Processor AutoRun registry entries
    """

    REGISTRY_KEY = r"Software\\Microsoft\\Command Processor"
    REGISTRY_VALUE = "AutoRun"

    def add_script(self, script_path: "Union[str, Path]") -> bool:
        """
        Add script to AutoRun, preserving existing commands
        """
        script_path = str(script_path)

        try:
            with self._open_registry_key() as key:
                tokens = self._get_current_tokens(key)

                if not self._script_exists_in_tokens(tokens, script_path):
                    new_tokens = (
                        [script_path, " & "] + tokens if tokens else [script_path]
                    )
                    self._set_autorun_value(key, "".join(new_tokens))

                return True
        except Exception:
            logger.info("Failed to add script to AutoRun")
            return False

    def remove_script(self, script_path: Union[str, Path]) -> bool:
        """
        Remove script from AutoRun, preserving other commands
        """
        script_path = str(script_path)

        try:
            with self._open_registry_key() as key:
                tokens = self._get_current_tokens(key)

                if self._script_exists_in_tokens(tokens, script_path):
                    cleaned_tokens = self._remove_script_tokens(tokens, script_path)

                    if cleaned_tokens:
                        self._set_autorun_value(key, " ".join(cleaned_tokens))
                    else:
                        self._delete_autorun_value(key)

                return True
        except Exception:
            logger.info("Failed to remove script from AutoRun")
            return False

    def get_current_commands(self) -> List[str]:
        """
        Get list of current AutoRun commands
        """
        try:
            with self._open_registry_key() as key:
                tokens = self._get_current_tokens(key)
                return [
                    token.strip()
                    for token in tokens
                    if not self._is_separator(token) and token.strip()
                ]
        except Exception:
            logger.info("Failed to get current AutoRun value")
            return []

    def _open_registry_key(self):
        """
        Context manager for registry key access
        """
        try:
            return winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                self.REGISTRY_KEY,
                0,
                winreg.KEY_READ | winreg.KEY_SET_VALUE,
            )
        except FileNotFoundError:
            logger.info("Failed to open registry key")
            logger.info("Creating registry key: %s", self.REGISTRY_KEY)

            return winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.REGISTRY_KEY)

    def _get_current_tokens(self, key) -> List[str]:
        """
        Get current AutoRun value as tokens
        """
        try:
            existing_value, _ = winreg.QueryValueEx(key, self.REGISTRY_VALUE)
            return self._tokenize_autorun(existing_value)
        except FileNotFoundError:
            logger.info("Failed to get current AutoRun value")
            return []

    def _is_our_script(self, token: str, script_path: str) -> bool:
        """
        Check if token is our script (ignoring whitespace)
        """
        return token.strip() == script_path

    def _is_separator(self, token: str) -> bool:
        """
        Check if token is a command separator that can be used to chain
        commands in the AutoRun value
        """
        return token.strip() in ["&", "&&", "|", "||"]

    def _tokenize_autorun(self, autorun_value: str) -> List[str]:
        """
        Tokenize AutoRun value preserving commands, separators, and spacing.
        Simple character-by-character parsing approach.
        """
        if not autorun_value:
            return []

        tokens = []
        current_token = ""
        i = 0

        while i < len(autorun_value):
            char = autorun_value[i]

            if char in "&|":
                # Save current token if exists
                if current_token:
                    tokens.append(current_token)
                    current_token = ""

                # Handle double operators (&&, ||)
                if i + 1 < len(autorun_value) and autorun_value[i + 1] == char:
                    tokens.append(char + char)  # && or ||
                    i += 2
                else:
                    tokens.append(char)  # & or |
                    i += 1
            else:
                current_token += char
                i += 1

        if current_token:
            tokens.append(current_token)

        return tokens

    def _script_exists_in_tokens(self, tokens: List[str], script_path: str) -> bool:
        """
        Check if script already exists in token list
        """
        return any(token.strip() == script_path for token in tokens)

    def _remove_script_tokens(self, tokens: List[str], script_path: str) -> List[str]:
        """
        Remove our script and clean up separators
        """
        result = []
        i = 0

        while i < len(tokens):
            if self._is_our_script(tokens[i], script_path):
                # Skip our script
                # Also skip the next separator if it exists
                if i + 1 < len(tokens) and self._is_separator(tokens[i + 1]):
                    i += 2  # Skip script + separator
                else:
                    i += 1  # Skip just the script
            else:
                result.append(tokens[i].strip())
                i += 1

        return result

    def _set_autorun_value(self, key, value: str):
        """
        Set AutoRun registry value
        """
        winreg.SetValueEx(key, self.REGISTRY_VALUE, 0, winreg.REG_SZ, value)

    def _delete_autorun_value(self, key):
        """
        Delete AutoRun registry value
        """
        winreg.DeleteValue(key, self.REGISTRY_VALUE)


class WindowsInterceptor(CommandInterceptor):
    def __init__(self):
        super().__init__(InterceptorType.WINDOWS_BAT)
        self.scripts_dir = Path.home() / "AppData" / "Local" / "safety"
        # Ensure the scripts directory exists
        # This makes sure that if a user is using a sandboxed Python
        # installation from the Microsoft Store, the directory is created and
        # the .resolve() method works correctly.
        self.scripts_dir.mkdir(parents=True, exist_ok=True)
        self.scripts_dir = self.scripts_dir.resolve()

        self.backup_dir = self.scripts_dir / "backups"
        self.backup_win_env_path = self.backup_dir / "path_backup.txt"
        self.venv_pwshell_wrapper_path = self.scripts_dir / "venv-wrappers.ps1"
        self.venv_cmd_wrapper_path = self.scripts_dir / "venv-wrappers.bat"

        # Update these markers could be a breaking change; be careful to handle
        # backward compatibility
        self.marker_start = ">>> Safety >>>"
        self.marker_end = "<<< Safety <<<"

    def _backup_path_env(self, path_content: str) -> None:
        """
        Backup current PATH to a file
        """
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        metadata_lines = self._generate_metadata_content(prepend="")

        lines = (
            (self.marker_start,) + metadata_lines + (path_content,) + (self.marker_end,)
        )

        content = "\n".join(lines) + "\n"

        self.backup_win_env_path.write_text(content)

    def _generate_bat_content(self, tool_name: str) -> str:
        """
        Generate the content for the bat with metadata
        """
        metadata_lines = self._generate_metadata_content(prepend="REM")

        no_echo = "@echo off"
        wrapper = f"safety {tool_name} %*"
        lines = (
            (
                no_echo,
                f"REM {self.marker_start}",
            )
            + metadata_lines
            + (wrapper,)
            + (f"REM {self.marker_end}",)
        )

        return "\n".join(lines) + "\n"

    def __generate_cmd_wrapper_content(self, binaries: List[str]) -> str:
        """
        Generate the content for the cmd wrapper with metadata
        """
        metadata_lines = self._generate_metadata_content(prepend="REM")

        no_echo = "@echo off"
        wrappers = []
        for binary in binaries:
            wrapper = f"doskey {binary}={self.scripts_dir / binary}.bat $*"
            wrappers.append(wrapper)

        comment_top = f"{no_echo}\nREM {self.marker_start}"
        comment_bottom = f"REM {self.marker_end}"
        lines = (
            comment_top,
            *metadata_lines,
            *wrappers,
            comment_bottom,
        )

        return "\n".join(lines) + "\n"

    def __generate_powershell_wrapper_content(self, binaries: List[str]) -> str:
        """
        Generate the content for the powershell wrapper with PowerShell functions
        """
        metadata_lines = self._generate_metadata_content(prepend="#")

        wrappers = []
        for binary in binaries:
            bat_path = self.scripts_dir / f"{binary}.bat"
            wrapper = f"""function {binary} {{
        param([Parameter(ValueFromRemainingArguments)]$args)
        & "{bat_path}" @args
    }}"""
            wrappers.append(wrapper)

        comment_top = f"# {self.marker_start}"
        comment_bottom = f"# {self.marker_end}"
        lines = [
            comment_top,
            *metadata_lines,
            *wrappers,
            comment_bottom,
        ]

        return "\n".join(lines) + "\n"

    def __generate_powershell_sourcing_content(self, script_path: Path) -> str:
        """
        Generate the PowerShell sourcing content with Safety markers
        """
        lines = [
            f"# {self.marker_start}",
            f". {script_path}",
            f"# {self.marker_end}",
        ]

        return "\n".join(lines) + "\n"

    def __get_powershell_profiles(self) -> Dict[str, Path]:
        """
        Get the CurrentUserAllHosts profile paths for available PowerShell versions
        Returns a dictionary with shell executable as key and profile path as value
        """
        profiles = {}
        shells = [("powershell.exe", "PowerShell 5.1"), ("pwsh.exe", "PowerShell 7+")]

        for shell, shell_name in shells:
            try:
                import subprocess

                # Check if the shell is available
                try:
                    subprocess.run(
                        [shell, "-Command", "exit"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                except FileNotFoundError:
                    logger.info(f"{shell_name} not found, skipping profile setup")
                    continue

                # Get the CurrentUserAllHosts profile path
                cmd = [
                    shell,
                    "-Command",
                    "Get-Variable PROFILE -ValueOnly | Select-Object -ExpandProperty CurrentUserAllHosts",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=False
                )
                result_stdout = result.stdout.strip()
                if result.returncode == 0 and result_stdout:
                    profile_path = Path(result_stdout)
                    # Ensure parent directory exists
                    profile_path.parent.mkdir(parents=True, exist_ok=True)
                    # Create the file if it doesn't exist
                    if not profile_path.exists():
                        profile_path.touch()
                    profiles[shell] = profile_path
                    logger.info(f"Found {shell_name} profile at {profile_path}")
                else:
                    logger.info(
                        f"Failed to get {shell_name} profile path: {result.stderr.strip()}"
                    )
            except Exception as e:
                logger.info(f"Error while getting {shell_name} profile: {str(e)}")

        # Fallback to default profile path if no profiles were found
        if not profiles:
            default_path = (
                Path.home() / "Documents" / "WindowsPowerShell" / "profile.ps1"
            )
            default_path.parent.mkdir(parents=True, exist_ok=True)
            if not default_path.exists():
                default_path.touch()
            profiles["fallback"] = default_path
            logger.info(f"Using fallback profile at {default_path}")

        return profiles

    def _install_venv_wrappers(self, binaries: List[str]):
        """
        Install specific wrappers for virtualenv support on Windows
        """
        # Refresh scripts content
        # CMD wrappers
        cmd_wrapper = self.__generate_cmd_wrapper_content(binaries)
        self.venv_cmd_wrapper_path.write_text(cmd_wrapper)

        # PowerShell wrappers
        powershell_wrapper = self.__generate_powershell_wrapper_content(binaries)
        self.venv_pwshell_wrapper_path.write_text(powershell_wrapper)

        # Link CMD wrapper to Autorun
        autorun_manager = AutoRunManager()
        autorun_manager.add_script(self.venv_cmd_wrapper_path)

        # Link Powershell wrapper to Powershell PROFILEs
        profiles = self.__get_powershell_profiles()
        pwshell_source = self.__generate_powershell_sourcing_content(
            self.venv_pwshell_wrapper_path
        )

        for _, profile_path in profiles.items():
            try:
                # Read current content or create empty string if file doesn't exist yet
                try:
                    profile_content = profile_path.read_text()
                except FileNotFoundError:
                    profile_path.parent.mkdir(parents=True, exist_ok=True)
                    profile_content = ""

                # Add sourcing command if not already present
                if self.marker_start not in profile_content:
                    if profile_content and not profile_content.endswith("\n"):
                        profile_content += "\n"
                    profile_content += pwshell_source
                    profile_path.write_text(profile_content)
                    logger.info(f"Added PowerShell wrapper to {profile_path}")
            except Exception as e:
                logger.info(
                    f"Failed to update PowerShell profile at {profile_path}: {str(e)}"
                )

    def _remove_venv_wrappers(self):
        """
        Remove specific wrappers for virtualenv support on Windows.

        This is an indempotent operation.
        """
        # For CMD
        autorun_manager = AutoRunManager()
        autorun_manager.remove_script(self.venv_cmd_wrapper_path)

        # For PowerShell
        # Remove Powershell wrapper from all PowerShell profiles
        profiles = self.__get_powershell_profiles()

        for _, profile_path in profiles.items():
            try:
                if profile_path.exists():
                    profile_content = profile_path.read_text()

                    if self.marker_start not in profile_content:
                        logger.info(f"PowerShell wrapper not found in {profile_path}")
                        continue

                    # Look for our sourcing line and the comment block we added
                    # Remove the entire block including comments
                    lines = profile_content.splitlines()
                    new_lines = []
                    skip_block = False

                    for line in lines:
                        if self.marker_start in line:
                            skip_block = True
                            continue

                        if skip_block:
                            if self.marker_end in line:
                                skip_block = False
                            continue

                        new_lines.append(line)

                    new_content = "\n".join(new_lines)
                    new_content = re.sub(r"\n{3,}", "\n\n", new_content)

                    profile_path.write_text(new_content)
                    logger.info(f"Removed PowerShell wrapper from {profile_path}")
            except Exception as e:
                logger.info(
                    f"Failed to remove PowerShell wrapper from {profile_path}: {str(e)}"
                )

    def _batch_install_tools(self, tools: List[Tool]) -> bool:
        """
        Install interceptors for multiple tools at once
        """
        try:
            wrappers = []
            for tool in tools:
                for binary in tool.binary_names:
                    # TODO: Switch to binary once we support safety pip3, etc.
                    wrapper = self._generate_bat_content(tool.name)
                    wrappers.append((binary, wrapper))

            if not wrappers:
                return False

            # Create safety directory if it doesn't exist
            self.scripts_dir.mkdir(parents=True, exist_ok=True)

            for binary, wrapper in wrappers:
                wrapper_path = self.scripts_dir / f"{binary}.bat"
                wrapper_path.write_text(wrapper)

            # Virtualenv environment wrappers
            all_binaries = [binary for tool in tools for binary in tool.binary_names]
            self._install_venv_wrappers(binaries=all_binaries)

            # Add scripts directory to PATH if needed
            self._update_path()

            return True

        except Exception as e:
            logger.info("Failed to batch install tools: %s", e)
            return False

    def _batch_remove_tools(self, tools: List[Tool]) -> bool:
        """
        Remove interceptors for multiple tools at once.

        Note: We don't support removing specific tools yet,
        so we remove all tools.
        """
        try:
            self._update_path(remove=True)
            if self.scripts_dir.exists():
                shutil.rmtree(self.scripts_dir)

            self._remove_venv_wrappers()

            return True

        except Exception as e:
            logger.info("Failed to batch remove tools: %s", e)
            return False

    def _update_path(self, remove: bool = False) -> bool:
        """
        Update Windows PATH environment variable
        """

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_ALL_ACCESS
            ) as key:
                # Get current PATH value
                try:
                    path_val = winreg.QueryValueEx(key, "PATH")[0]
                    self._backup_path_env(path_content=path_val)
                except FileNotFoundError:
                    path_val = ""

                # Convert to Path objects
                paths = [Path(p) for p in path_val.split(os.pathsep) if p]

                if remove:
                    if self.scripts_dir in paths:
                        paths.remove(self.scripts_dir)
                        new_path = os.pathsep.join(str(p) for p in paths)
                        winreg.SetValueEx(
                            key, "PATH", 0, winreg.REG_EXPAND_SZ, new_path
                        )
                else:
                    if self.scripts_dir not in paths:
                        paths.insert(0, self.scripts_dir)  # Add to beginning
                        new_path_val = os.pathsep.join(str(p) for p in paths)
                        winreg.SetValueEx(
                            key, "PATH", 0, winreg.REG_EXPAND_SZ, new_path_val
                        )

            return True
        except Exception as e:
            logger.info("Failed to update PATH: %s", e)
            return False
