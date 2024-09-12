

from pathlib import Path
from safety_schemas.models import Ecosystem, FileType
from typer import FileTextWrite

from .python.main import PythonFile


class InspectableFileContext:
    """
    Context manager for handling the lifecycle of an inspectable file.

    This class ensures that the file is properly opened and closed, handling any
    exceptions that may occur during the process.
    """

    def __init__(self, file_path: Path,
                 file_type: FileType) -> None:
        """
        Initializes the InspectableFileContext.

        Args:
            file_path (Path): The path to the file.
            file_type (FileType): The type of the file.
        """
        self.file_path = file_path
        self.inspectable_file = None
        self.file_type = file_type

    def __enter__(self): # TODO: Handle permission issue /Applications/...
        """
        Enters the runtime context related to this object.

        Opens the file and creates the appropriate inspectable file object based on the file type.

        Returns:
            The inspectable file object.
        """
        try:
            file: FileTextWrite = open(self.file_path, mode='r+') # type: ignore
            self.inspectable_file = TargetFile.create(file_type=self.file_type, file=file)
        except Exception as e:
            # TODO: Report this
            pass

        return self.inspectable_file

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exits the runtime context related to this object.

        Ensures that the file is properly closed.
        """
        if self.inspectable_file:
            self.inspectable_file.file.close()

class TargetFile():
    """
    Factory class for creating inspectable file objects based on the file type and ecosystem.
    """

    @classmethod
    def create(cls, file_type: FileType, file: FileTextWrite):
        """
        Creates an inspectable file object based on the file type and ecosystem.

        Args:
            file_type (FileType): The type of the file.
            file (FileTextWrite): The file object.

        Returns:
            An instance of the appropriate inspectable file class.

        Raises:
            ValueError: If the ecosystem or file type is unsupported.
        """
        if file_type.ecosystem == Ecosystem.PYTHON:
            return PythonFile(file=file, file_type=file_type)

        raise ValueError("Unsupported ecosystem or file type: " \
                         f"{file_type.ecosystem}:{file_type.value}")
