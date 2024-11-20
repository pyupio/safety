from pathlib import Path
from typing import List
from safety_schemas.models import FileType, ConfigModel
from inspectable_file_context import InspectableFileContext

def read_dependency_files(file_paths: List[Path], file_types: List[FileType], config=None):
    """
    Reads and processes a list of dependency files, parsing their content into structured models.

    Args:
        file_paths (List[Path]): A list of file paths to process.
        file_types (List[FileType]): Corresponding file types for each file path.
        config (ConfigModel): Configuration for the scan (optional).

    Yields:
        Generator[Tuple[Path, FileModel]]: Each file path and its structured model.
    """
    if not config:
        config = ConfigModel()

    for file_path, file_type in zip(file_paths, file_types):
        file_path = Path(file_path)

        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        print(file_path, file_type)
        # Wrap the file in InspectableFileContext
        with InspectableFileContext(file_path, file_type=file_type) as inspectable_file:
            if inspectable_file:  # Ensure the file was successfully wrapped
                inspectable_file.inspect(config=config)
                inspectable_file.remediate()
                yield file_path, inspectable_file
            else:
                print(f"Unable to process file: {file_path}")

