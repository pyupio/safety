from abc import ABC, abstractmethod
from typing import List

from safety_schemas.models import Ecosystem, FileType, ConfigModel, \
    DependencyResultModel
from typer import FileTextWrite

NOT_IMPLEMENTED = "Not implemented funtion"


class Inspectable(ABC):

    @abstractmethod
    def inspect(self, config: ConfigModel) -> DependencyResultModel:
        return NotImplementedError(NOT_IMPLEMENTED)

    
class Remediable(ABC):

    @abstractmethod
    def remediate(self):
        return NotImplementedError(NOT_IMPLEMENTED)
    

class InspectableFile(Inspectable):
    
    def __init__(self, file: FileTextWrite):
        self.file = file
        self.ecosystem: Ecosystem
        self.file_type: FileType
        self.dependency_results: DependencyResultModel = \
            DependencyResultModel(dependencies=[])



