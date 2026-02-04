from pathlib import Path
from ...filesystem import FsRuntime
from ...models import FileIntegrity
from ...events.payloads.tool import (
    ToolInfo,
    PackageManagerTool,
    VcsTool,
    ContainerTool,
    IdeTool,
    AiTool,
)


def collect_tool_info(
    path: Path, tool_name: str, tool_subtype: str, fs: FsRuntime
) -> ToolInfo:
    """
    Collect tool information including version and metadata.

    Args:
        path: Path to the tool executable
        tool_name: Name of the tool
        tool_subtype: Tool subtype string
        fs: Filesystem runtime

    Returns:
        ToolInfo payload object
    """
    realpath = fs.realpath(path)

    # Calculate file integrity
    integrity = FileIntegrity.from_path(realpath, fs)

    # TODO: Extract version
    version = None

    # Determine aliases
    aliases = []
    if realpath != path:
        aliases.append(str(path))

    # Create appropriate tool payload based on subtype
    common_args = {
        "canonical_path": str(realpath),
        "name": tool_name,
        "version": version,
        "integrity": integrity,
        "aliases": aliases,
    }

    if tool_subtype.startswith("python."):
        return PackageManagerTool(**common_args)
    elif tool_subtype.startswith("vcs."):
        return VcsTool(**common_args)
    elif tool_subtype.startswith("container."):
        return ContainerTool(**common_args)
    elif tool_subtype.startswith("ide."):
        return IdeTool(**common_args)
    elif tool_subtype.startswith("ai."):
        return AiTool(**common_args)
    else:
        # Default to package manager for unknown types
        return PackageManagerTool(**common_args)
