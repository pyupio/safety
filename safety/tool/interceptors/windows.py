import logging
import os
import shutil
from pathlib import Path
from sys import platform
from typing import TYPE_CHECKING, List

from .base import CommandInterceptor, Tool
from .types import InterceptorType

if TYPE_CHECKING or platform == "win32":
    import winreg

LOG = logging.getLogger(__name__)


class WindowsInterceptor(CommandInterceptor):
    def __init__(self):
        super().__init__(InterceptorType.WINDOWS_BAT)
        self.scripts_dir = Path.home() / "AppData" / "Local" / "safety"
        self.backup_dir = self.scripts_dir / "backups"
        self.backup_win_env_path = self.backup_dir / "path_backup.txt"

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

            # Add scripts directory to PATH if needed
            self._update_path()

            return True

        except Exception:
            LOG.info("Failed to batch install tools")
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

            return True

        except Exception:
            LOG.info("Failed to batch remove tools.")
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
        except Exception:
            LOG.info("Failed to update PATH")
            return False

    def _install_tool(self, tool: Tool) -> bool:
        """Individual tool installation (fallback method)"""
        return self._batch_install_tools([tool])

    def _remove_tool(self, tool: Tool) -> bool:
        """Individual tool removal (fallback method)"""
        return self._batch_remove_tools([tool])

    def _validate_installation(self, tool: Tool) -> bool:
        try:
            # Check if batch files exist
            for binary in tool.binary_names:
                batch_script = self.scripts_dir / f"{binary}.bat"
                if not batch_script.exists():
                    return False

            # Check if directory is in PATH
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ
            )
            path = winreg.QueryValueEx(key, "PATH")[0]
            winreg.CloseKey(key)

            return str(self.scripts_dir) in path

        except Exception:
            return False
