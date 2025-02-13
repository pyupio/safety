from pathlib import Path
from typing import Optional

from pydantic.dataclasses import dataclass


@dataclass
class UnverifiedProjectModel:
    """
    Data class representing an unverified project model.
    """

    id: Optional[str]
    project_path: Path
    created: bool
    name: Optional[str] = None
    url_path: Optional[str] = None
