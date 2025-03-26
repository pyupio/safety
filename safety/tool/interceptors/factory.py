from sys import platform
from typing import Optional
from .types import InterceptorType
from .unix import UnixAliasInterceptor
from .windows import WindowsInterceptor
from .base import CommandInterceptor


def create_interceptor(
    interceptor_type: Optional[InterceptorType] = None,
) -> CommandInterceptor:
    """
    Create appropriate interceptor based on OS and type
    """
    interceptor_map = {
        InterceptorType.UNIX_ALIAS: UnixAliasInterceptor,
        InterceptorType.WINDOWS_BAT: WindowsInterceptor,
    }

    if interceptor_type:
        return interceptor_map[interceptor_type]()

    # Auto-select based on OS
    if platform == "win32":
        return interceptor_map[InterceptorType.WINDOWS_BAT]()

    if platform in ["linux", "linux2", "darwin"]:
        # Default to alias-based on Unix-like systems
        return interceptor_map[InterceptorType.UNIX_ALIAS]()

    raise NotImplementedError(f"Platform '{platform}' is not supported.")
