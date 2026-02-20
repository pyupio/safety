from __future__ import annotations

from pathlib import Path
import platform
from typing import Iterator
from collections import defaultdict

from ...events.payloads.links import ExecutionContextRelation, ToolRelations
from ...models import Candidate, Detection, DetectionKind
from ...filesystem import FsRuntime
from .collectors import collect_tool_info
from ...registry import ScanRefRegistry
from ...context import DetectContext


class ToolDetector:
    TOOL_PATTERNS = {
        "pip": "package_manager:pip",
        "pip3": "package_manager:pip",
        "poetry": "package_manager:poetry",
        "pipenv": "package_manager:pipenv",
        "conda": "package_manager:conda",
        "uv": "package_manager:uv",
        "rye": "package_manager:rye",
        "pdm": "package_manager:pdm",
        "hatch": "package_manager:hatch",
        "git": "vcs:git",
        "docker": "container:docker",
        "podman": "container:podman",
        "cursor": "ide:cursor",
        "windsurf": "ide:windsurf",
        "claude": "ai:claude",
        "codex": "ai:codex",
    }

    _WINDOWS_SYSTEM_PATHS = [
        Path("C:/Windows"),
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
    ]

    _UNIX_SYSTEM_PATHS = (
        Path("/bin"),
        Path("/sbin"),
        Path("/usr/bin"),
        Path("/usr/sbin"),
        Path("/usr/local/bin"),
    )

    _MACOS_EXTRA_PATHS = (
        Path("/System"),
        Path("/Library"),
    )

    def _validate(self, path: Path, fs: FsRuntime) -> str | None:
        """Validate path is a known tool. Returns subtype or None."""
        if not fs.is_file(path) or not fs.is_executable(path):
            return None

        base, _, _ = path.name.lower().partition(".")
        return self.TOOL_PATTERNS.get(base)

    def _get_stable_id(self, path: Path, fs: FsRuntime) -> str:
        """Generate stable ID based on inode."""
        try:
            stat = fs.stat(path)
            return f"tool:{path.stem.lower()}:{stat.st_dev}:{stat.st_ino}"
        except (OSError, PermissionError):
            return f"tool:{path.stem.lower()}:{path}"

    def _detect_tool(
        self,
        path: Path,
        subtype: str,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        scan_registry: ScanRefRegistry,
        source: str = "DIRECT",
        aliases: list[str] | None = None,
    ) -> Detection | None:
        """Core detection logic. Returns Detection or None if already seen."""
        stable_id = self._get_stable_id(path, fs)

        if scan_registry.is_seen(stable_id):
            return None

        tool_name = path.stem.lower()
        tool_info = collect_tool_info(path, tool_name, subtype, fs)

        if not tool_info:
            return None

        scan_registry.register_other(stable_id)

        tool_info.aliases = aliases or []

        relations = ToolRelations(execution_context=exec_context_ref)
        tool_info.links = relations

        return Detection(
            kind=DetectionKind.TOOL,
            subtype=subtype,
            stable_id=stable_id,
            primary_path=str(path),
            scope="system" if self._is_system_tool(path) else "user",
            found_via=[source],
            meta=tool_info,
        )

    def _is_system_tool(self, path: Path) -> bool:
        """
        Determine if a tool is a system tool based on its path.

        Args:
            path (Path): The path to the tool.

        Returns:
            bool: True if the tool is a system tool, False otherwise.
        """

        system = platform.system()

        if system == "Windows":
            paths = self._WINDOWS_SYSTEM_PATHS
        elif system == "Darwin":
            paths = self._UNIX_SYSTEM_PATHS + self._MACOS_EXTRA_PATHS
        else:
            paths = self._UNIX_SYSTEM_PATHS

        return any(path.is_relative_to(p) for p in paths)

    def detect(self, candidate: Candidate, ctx: DetectContext) -> Iterator[Detection]:
        """Detect tool from a single candidate."""

        fs: FsRuntime = ctx.fs
        scan_registry: "ScanRefRegistry" = ctx.registry

        exec_context_ref: ExecutionContextRelation = ctx.exec_ctx_rel

        subtype = self._validate(candidate.path, fs)

        if not subtype:
            return

        detection = self._detect_tool(
            path=candidate.path,
            subtype=subtype,
            fs=fs,
            exec_context_ref=exec_context_ref,
            scan_registry=scan_registry,
            source=candidate.source,
        )

        if detection:
            yield detection

    def scan_directory(
        self,
        directory_path: Path,
        fs: FsRuntime,
        exec_context_ref: ExecutionContextRelation,
        scan_registry: ScanRefRegistry,
        source: str = "ENV_BIN_SCAN",
    ) -> Iterator[Detection]:
        if not fs.is_dir(directory_path):
            return

        try:
            import os

            # Group by (size, subtype) within this directory
            tools_by_signature: dict[tuple, list[tuple[Path, str]]] = defaultdict(list)

            with os.scandir(directory_path) as entries:
                for entry in entries:
                    if not entry.is_file(follow_symlinks=True):
                        continue

                    path = Path(entry.path)
                    subtype = self._validate(path, fs)

                    if not subtype:
                        continue

                    try:
                        stat = entry.stat()
                        signature = (stat.st_size, subtype)
                        tools_by_signature[signature].append((path, subtype))
                    except (OSError, PermissionError):
                        continue

            # Emit one detection per unique signature
            for signature, tool_entries in tools_by_signature.items():
                primary_path, subtype = tool_entries[0]
                aliases = [t[0].name for t in tool_entries[1:]]

                detection = self._detect_tool(
                    path=primary_path,
                    subtype=subtype,
                    fs=fs,
                    exec_context_ref=exec_context_ref,
                    scan_registry=scan_registry,
                    source=source,
                    aliases=aliases,
                )
                if detection:
                    yield detection

        except (OSError, PermissionError):
            return
