from abc import ABC, abstractmethod

from safety_schemas.models import (
    Ecosystem,
    FileType,
    ConfigModel,
    DependencyResultModel,
)
from typer import FileTextWrite

NOT_IMPLEMENTED = "Not implemented funtion"


class Inspectable(ABC):
    """
    Abstract base class defining the interface for objects that can be inspected for dependencies.
    """

    @abstractmethod
    def inspect(self, config: ConfigModel) -> None:
        """
        Inspects the object and populates the dependency analysis results in-place.

        Args:
            config (ConfigModel): The configuration model for inspection.
        """
        raise NotImplementedError(NOT_IMPLEMENTED)


class Remediable(ABC):
    """
    Abstract base class defining the interface for objects that can be remediated.
    """

    @abstractmethod
    def remediate(self) -> None:
        """
        Remediates the object to address any detected issues.
        """
        raise NotImplementedError(NOT_IMPLEMENTED)


class InspectableFile(Inspectable):
    """
    Represents an inspectable file within a specific ecosystem and file type.
    """

    def __init__(self, file: FileTextWrite):
        """
        Initializes an InspectableFile instance.

        Args:
            file (FileTextWrite): The file to be inspected.
        """
        self.file = file
        self.ecosystem: Ecosystem
        self.file_type: FileType
        self.dependency_results: DependencyResultModel = DependencyResultModel(
            dependencies=[]
        )
