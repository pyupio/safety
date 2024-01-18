from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic.dataclasses import dataclass

class FormatMixin:

    @classmethod
    def is_format(cls, format_sub: Optional[Enum], format_instance: Enum):
        """ Check if the value is a variant of the specified format. """
        if not format_sub:
            return False

        if format_sub is format_instance:
            return True

        prefix =  format_sub.value.split('@')[0]
        return prefix == format_instance.value
    
    @property
    def version(self):
        """ Return the version of the format. """
        result = self.value.split('@')

        if len(result) == 2:
            return result[1]
        
        return None


class ScanOutput(FormatMixin, str, Enum):
    JSON = "json"
    SPDX = "spdx"
    SPDX_2_3 = "spdx@2.3"
    SPDX_2_2 = "spdx@2.2"
    HTML = "html"

    SCREEN = "screen"
    NONE = "none"

    def is_silent(self):
        return self in (ScanOutput.JSON, ScanOutput.SPDX, ScanOutput.SPDX_2_3, ScanOutput.SPDX_2_2, ScanOutput.HTML)


class ScanExport(FormatMixin, str, Enum):
    JSON = "json"
    SPDX = "spdx"
    SPDX_2_3 = "spdx@2.3"
    SPDX_2_2 = "spdx@2.2"
    HTML = "html"    

    def get_default_file_name(self, tag: int):
        
        if self is ScanExport.JSON:
            return f"safety-report-{tag}.json"
        elif self in [ScanExport.SPDX, ScanExport.SPDX_2_3, ScanExport.SPDX_2_2]:
            return f"safety-report-spdx-{tag}.json"
        elif self is ScanExport.HTML:
            return f"safety-report-{tag}.html"
        else:
            raise ValueError("Unsupported scan export type")


class SystemScanOutput(str, Enum):
    JSON = "json"
    SCREEN = "screen"

    def is_silent(self):
        return self in (SystemScanOutput.JSON,)   

class SystemScanExport(str, Enum):
    JSON = "json"

@dataclass
class UnverifiedProjectModel():
    id: Optional[str]
    project_path: Path
    created: bool
    name: Optional[str] = None
    url_path: Optional[str] = None    
