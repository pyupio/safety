from pathlib import Path
from typing import Optional

from pydantic.dataclasses import dataclass
from safety_schemas.models.events.payloads import InitExitStep


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


class StepTracker:
    def __init__(self):
        self.current_step: InitExitStep = InitExitStep.UNKNOWN
