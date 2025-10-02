from pathlib import Path
import logging
from safety_schemas.models import Ecosystem, FileType
from typer import FileTextWrite

from .python.main import PythonFile
from ...encoding import detect_encoding, safe_read_file

logger = logging.getLogger(__name__)


class InspectableFileContext:
    """
    Context manager for handling the lifecycle of an inspectable file.

    This class ensures that the file is properly opened and closed, handling any
    exceptions that may occur during the process.
    """

    def __init__(self, file_path: Path, file_type: FileType, ignore_errors: bool = False) -> None:
        """
        Initializes the InspectableFileContext.

        Args:
            file_path (Path): The path to the file.
            file_type (FileType): The type of the file.
            ignore_errors (bool): If True, skip files that cannot be read instead of raising.
        """
        self.file_path = file_path
        self.inspectable_file = None
        self.file_type = file_type
        self.ignore_errors = ignore_errors
        self.error_message = None

    def __enter__(self):  # TODO: Handle permission issue /Applications/...
        """
        Enters the runtime context related to this object.

        Opens the file and creates the appropriate inspectable file object based on the file type.

        Returns:
            The inspectable file object or None if errors are ignored.
        """
        try:
            encoding = detect_encoding(self.file_path)
            file: FileTextWrite = open(self.file_path, mode="r+", encoding=encoding)  # type: ignore
            self.inspectable_file = TargetFile.create(
                file_type=self.file_type, file=file
            )
        except Exception as e:
            error_msg = f"Error opening file {self.file_path}: {str(e)}"
            self.error_message = error_msg

            if self.ignore_errors:
                logger.warning(error_msg)
            else:
                logger.exception(error_msg)
                raise

        return self.inspectable_file

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exits the runtime context related to this object.

        Ensures that the file is properly closed.
        """
        if self.inspectable_file:
            self.inspectable_file.file.close()


class TargetFile:
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

        raise ValueError(
            "Unsupported ecosystem or file type: "
            f"{file_type.ecosystem}:{file_type.value}"
        )
