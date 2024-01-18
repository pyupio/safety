

from pathlib import Path
from safety_schemas.models import Ecosystem, FileType
from typer import FileTextWrite

from .python.main import PythonFile


class InspectableFileContext:
    def __init__(self, file_path: Path, 
                 file_type: FileType) -> None:
        self.file_path = file_path
        self.inspectable_file = None
        self.file_type = file_type

    def __enter__(self): # TODO: Handle permission issue /Applications/...
        try:
            file: FileTextWrite = open(self.file_path, mode='r+') # type: ignore
            self.inspectable_file = TargetFile.create(file_type=self.file_type, file=file)
        except Exception as e:
            # TODO: Report this
            pass
        
        return self.inspectable_file

    def __exit__(self, exc_type, exc_value, traceback):
        if self.inspectable_file:
            self.inspectable_file.file.close()

class TargetFile():

    @classmethod
    def create(cls, file_type: FileType, file: FileTextWrite):
        if file_type.ecosystem == Ecosystem.PYTHON:
            return PythonFile(file=file, file_type=file_type)
        
        raise ValueError("Unsupported ecosystem or file type: " \
                         f"{file_type.ecosystem}:{file_type.value}")
