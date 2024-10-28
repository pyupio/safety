from enum import Enum
from typing import Optional

class FormatMixin:
    """
    Mixin class providing format-related utilities for Enum classes.
    """

    @classmethod
    def is_format(cls, format_sub: Optional[Enum], format_instance: Enum) -> bool:
        """
        Check if the value is a variant of the specified format.

        Args:
            format_sub (Optional[Enum]): The format to check.
            format_instance (Enum): The instance of the format to compare against.

        Returns:
            bool: True if the format matches, otherwise False.
        """
        if not format_sub:
            return False

        if format_sub is format_instance:
            return True

        prefix =  format_sub.value.split('@')[0]
        return prefix == format_instance.value

    @property
    def version(self) -> Optional[str]:
        """
        Return the version of the format.

        Returns:
            Optional[str]: The version of the format if available, otherwise None.
        """
        result = self.value.split('@')

        if len(result) == 2:
            return result[1]

        return None


class ScanOutput(FormatMixin, str, Enum):
    """
    Enum representing different scan output formats.
    """
    JSON = "json"
    SPDX = "spdx"
    SPDX_2_3 = "spdx@2.3"
    SPDX_2_2 = "spdx@2.2"
    HTML = "html"

    SCREEN = "screen"
    NONE = "none"

    def is_silent(self) -> bool:
        """
        Check if the output format is silent.

        Returns:
            bool: True if the output format is silent, otherwise False.
        """
        return self in (ScanOutput.JSON, ScanOutput.SPDX, ScanOutput.SPDX_2_3, ScanOutput.SPDX_2_2, ScanOutput.HTML)


class ScanExport(FormatMixin, str, Enum):
    """
    Enum representing different scan export formats.
    """
    JSON = "json"
    SPDX = "spdx"
    SPDX_2_3 = "spdx@2.3"
    SPDX_2_2 = "spdx@2.2"
    HTML = "html"

    def get_default_file_name(self, tag: int) -> str:
        """
        Get the default file name for the export format.

        Args:
            tag (int): A unique tag to include in the file name.

        Returns:
            str: The default file name.
        """
        if self is ScanExport.JSON:
            return f"safety-report-{tag}.json"
        elif self in [ScanExport.SPDX, ScanExport.SPDX_2_3, ScanExport.SPDX_2_2]:
            return f"safety-report-spdx-{tag}.json"
        elif self is ScanExport.HTML:
            return f"safety-report-{tag}.html"
        else:
            raise ValueError("Unsupported scan export type")


class SystemScanOutput(str, Enum):
    """
    Enum representing different system scan output formats.
    """
    JSON = "json"
    SCREEN = "screen"

    def is_silent(self) -> bool:
        """
        Check if the output format is silent.

        Returns:
            bool: True if the output format is silent, otherwise False.
        """
        return self in (SystemScanOutput.JSON,)

class SystemScanExport(str, Enum):
    """
    Enum representing different system scan export formats.
    """
    JSON = "json"
