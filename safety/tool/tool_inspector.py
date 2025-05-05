import asyncio
import functools
import os
import platform
import re
import shutil
from typing import Dict, List, Optional, Set, Union


from safety_schemas.models.events.payloads import ToolStatus, AliasConfig, IndexConfig
from safety_schemas.models.events.types import ToolType

import logging

logger = logging.getLogger(__name__)


class ToolInspector:
    """
    Inspects the system for installed tools managers and their versions.
    """

    COMMON_LOCATIONS = {
        # Common paths across many tools
        "COMMON": ["/usr/local/bin", "/usr/bin", "~/.local/bin"],
        # Tool-specific paths
        ToolType.PIP: [
            # Virtual environments
            "venv/bin",
            "env/bin",
            ".venv/bin",
            ".env/bin",
            # Python installations
            "/opt/python*/bin",
            # Windows specific
            "C:/Python*/Scripts",
            "%APPDATA%/Python/Python*/Scripts",
            # macOS specific
            "/Library/Frameworks/Python.framework/Versions/*/bin",
        ],
        ToolType.POETRY: [
            "~/.poetry/bin",
            # Windows
            "%APPDATA%/Python/poetry/bin",
            "%USERPROFILE%/.poetry/bin",
        ],
        ToolType.CONDA: [
            "~/miniconda3/bin",
            "~/anaconda3/bin",
            "/opt/conda/bin",
            "/opt/miniconda3/bin",
            "/opt/anaconda3/bin",
            # Windows
            "C:/ProgramData/Miniconda3",
            "C:/ProgramData/Anaconda3",
            "%USERPROFILE%/Miniconda3",
            "%USERPROFILE%/Anaconda3",
        ],
        ToolType.UV: [
            "~/.cargo/bin",
            # Windows
            "%USERPROFILE%/.cargo/bin",
        ],
        ToolType.NPM: [
            "~/.nvm/versions/node/*/bin",
            # Windows
            "%APPDATA%/npm",
            "C:/Program Files/nodejs",
        ],
    }

    # Command arguments to check version
    VERSION_ARGS = {
        ToolType.PIP: "--version",
        ToolType.UV: "--version",
        ToolType.NPM: "--version",
        ToolType.POETRY: "--version",
        ToolType.CONDA: "--version",
    }

    # Version parsing regex
    VERSION_REGEX = {
        ToolType.PIP: r"pip (\d+\.\d+(?:\.\d+)?)",
        ToolType.UV: r"uv (\d+\.\d+(?:\.\d+)?)",
        ToolType.NPM: r"(\d+\.\d+\.\d+)",
        ToolType.POETRY: r"Poetry version (\d+\.\d+\.\d+)",
        ToolType.CONDA: r"conda (\d+\.\d+(?:\.\d+)?)",
    }

    def __init__(self, timeout: float = 1.0):
        """
        Initialize the detector.

        Args:
            timeout: Command execution timeout in seconds
        """
        self.timeout = timeout
        self._found_paths: Dict[ToolType, Set[str]] = {t: set() for t in ToolType}

    # TODO: limit concurrency
    async def inspect_all_tools(self) -> List[ToolStatus]:
        """
        Inspect all tools installed in the system.

        Returns:
            List of ToolStatus objects for each found tool
        """
        tasks = []
        for tool_type in ToolType:
            tasks.append(self._find_tool_instances(tool_type))

        results: List[Union[List[ToolStatus], BaseException]] = await asyncio.gather(
            *tasks, return_exceptions=True
        )

        tools_inspected: List[ToolStatus] = []

        for tool_status in results:
            if isinstance(tool_status, list):
                tools_inspected.extend(tool_status)

        return tools_inspected

    async def _find_tool_instances(self, tool_type: ToolType) -> List[ToolStatus]:
        """
        Find all instances of a specific tool type.
        """
        # Find all executable paths
        paths = await self._find_executable_paths(tool_type)

        tasks = [self._check_tool(tool_type, path) for path in paths]
        results: List[
            Optional[Union[ToolStatus, BaseException]]
        ] = await asyncio.gather(*tasks, return_exceptions=True)

        tools_inspected: List[ToolStatus] = []

        for tool_status in results:
            if isinstance(tool_status, ToolStatus):
                tools_inspected.append(tool_status)

        return tools_inspected

    def _search_executable_paths(self, tool_type: ToolType) -> Set[str]:
        # Get the executable name
        exe_name = tool_type.value
        if platform.system() == "Windows":
            exe_name = f"{exe_name}.exe"

        paths = set()

        path_result = shutil.which(exe_name)
        if path_result:
            paths.add(os.path.abspath(path_result))

        for location_pattern in (
            self.COMMON_LOCATIONS["COMMON"] + self.COMMON_LOCATIONS[tool_type]
        ):
            if location_pattern.startswith("~"):
                location_pattern = os.path.expanduser(location_pattern)

            if "%" in location_pattern:
                location_pattern = os.path.expandvars(location_pattern)

            # Handle wildcards
            if "*" in location_pattern:
                # This is a simplified wildcard expansion - a more robust implementation
                # would use glob or similar, but this is faster for common cases
                base_dir = location_pattern.split("*")[0]
                if os.path.exists(base_dir):
                    for root, dirs, files in os.walk(base_dir, followlinks=False):
                        if exe_name in files:
                            exe_path = os.path.join(root, exe_name)
                            if os.access(exe_path, os.X_OK):
                                paths.add(os.path.abspath(exe_path))
            else:
                # Direct path check
                exe_path = os.path.join(location_pattern, exe_name)
                if os.path.exists(exe_path) and os.access(exe_path, os.X_OK):
                    paths.add(os.path.abspath(exe_path))

        return paths

    async def _find_executable_paths(self, tool_type: ToolType) -> Set[str]:
        """
        Find all executable paths for a tool type.
        """
        if self._found_paths[tool_type]:
            return self._found_paths[tool_type]
        paths = await asyncio.get_event_loop().run_in_executor(
            None, functools.partial(self._search_executable_paths, tool_type)
        )
        self._found_paths[tool_type] = paths
        return paths

    async def _kill_process(self, proc):
        """
        Helper method to kill a process safely.
        """
        if proc is None:
            return

        try:
            proc.kill()
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except Exception:
            logger.exception("Error killing process")

    async def _check_tool(self, tool_type: ToolType, path: str) -> Optional[ToolStatus]:
        """
        Check if a tool at a specific path is reachable and get its version.
        """
        proc = None
        try:
            version_arg = self.VERSION_ARGS[tool_type]

            proc = await asyncio.create_subprocess_exec(
                path,
                version_arg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )

                # Get data we need
                output = stdout.decode() + stderr.decode()
                returncode = proc.returncode

                # Clear references to help garbage collection
                proc = None

                # Extract version
                version_match = re.search(self.VERSION_REGEX[tool_type], output)
                version = version_match.group(1) if version_match else "unknown"

                AliasConfig(is_configured=True)
                IndexConfig(is_configured=True)

                return ToolStatus(
                    type=tool_type,
                    command_path=path,
                    version=version,
                    reachable=returncode == 0,
                    alias_config=None,
                    index_config=None,
                )
            except (asyncio.TimeoutError, TimeoutError):
                if proc:
                    await self._kill_process(proc)
                    # Clear references to help garbage collection
                    proc = None

                # Command timed out
                return ToolStatus(
                    type=tool_type,
                    command_path=path,
                    version="unknown",
                    reachable=False,
                )
        except Exception:
            logger.exception("Error checking tool")

            # Any other error means the tool is not reachable
            if proc:
                await self._kill_process(proc)
                # Clear reference to help garbage collection
                proc = None

            return ToolStatus(
                type=tool_type, command_path=path, version="unknown", reachable=False
            )
