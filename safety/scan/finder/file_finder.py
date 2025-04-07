# type: ignore
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from safety_schemas.models import Ecosystem, FileType


from .handlers import FileHandler, ECOSYSTEM_HANDLER_MAPPING

LOG = logging.getLogger(__name__)


def should_exclude(excludes: Set[Path], to_analyze: Path) -> bool:
    """
    Determines whether a given path should be excluded based on the provided exclusion set.

    Args:
        excludes (Set[Path]): Set of paths to exclude.
        to_analyze (Path): The path to analyze.

    Returns:
        bool: True if the path should be excluded, False otherwise.
    """

    if not to_analyze.is_absolute():
        to_analyze = to_analyze.resolve()

    for exclude in excludes:
        if not exclude.is_absolute():
            exclude = exclude.resolve()

        try:
            if to_analyze == exclude or to_analyze.relative_to(exclude):
                return True
        except ValueError:
            pass

    return False


class FileFinder:
    """ "
    Defines a common interface to agree in what type of components Safety is trying to
    find depending on the language type.
    """

    def __init__(
        self,
        max_level: int,
        ecosystems: List[Ecosystem],
        target: Path,
        live_status=None,
        exclude: Optional[List[str]] = None,
        include_files: Optional[Dict[FileType, List[Path]]] = None,
        handlers: Optional[Set[FileHandler]] = None,
    ) -> None:
        """
        Initializes the FileFinder with the specified parameters.

        Args:
            max_level (int): Maximum directory depth to search.
            ecosystems (List[Ecosystem]): List of ecosystems to consider.
            target (Path): Target directory to search.
            console: Console object for output.
            live_status: Live status object for updates.
            exclude (Optional[List[str]]): List of patterns to exclude from the search.
            include_files (Optional[Dict[FileType, List[Path]]]): Dictionary of files to include in the search.
            handlers (Optional[Set[FileHandler]]): Set of file handlers.
        """
        self.max_level = max_level
        self.target = target
        self.include_files = include_files

        # If no handlers are provided, initialize them from the ecosystem mapping
        if not handlers:
            handlers = set(
                ECOSYSTEM_HANDLER_MAPPING[ecosystem]() for ecosystem in ecosystems
            )

        self.handlers = handlers
        self.file_count = 0
        self.exclude_dirs: Set[Path] = set()
        self.exclude_files: Set[Path] = set()
        exclude = [] if not exclude else exclude

        # Populate the exclude_dirs and exclude_files sets based on the provided patterns
        for pattern in exclude:
            for path in Path(target).glob(pattern):
                if path.is_dir():
                    self.exclude_dirs.add(path)
                else:
                    self.exclude_files.add(path)

        self.live_status = live_status

    def process_directory(
        self, dir_path: str, max_deep: Optional[int] = None
    ) -> Tuple[str, Dict[str, Set[Path]]]:
        """
        Processes the specified directory to find files matching the handlers' criteria.

        Args:
            dir_path (str): The directory path to process.
            max_deep (Optional[int]): Maximum depth to search within the directory.

        Returns:
            Tuple[str, Dict[str, Set[Path]]]: The directory path and a dictionary of file types and their corresponding paths.
        """
        files: Dict[str, Set[Path]] = {}
        level: int = 0
        initial_depth = len(Path(dir_path).parts) - 1

        for root, dirs, filenames in os.walk(dir_path):
            root_path = Path(root)
            current_depth = len(root_path.parts) - initial_depth

            # Filter directories based on exclusion criteria
            dirs[:] = [
                d
                for d in dirs
                if not should_exclude(
                    excludes=self.exclude_dirs, to_analyze=(root_path / Path(d))
                )
            ]
            if dirs:
                LOG.info(f"Directories to inspect -> {', '.join(dirs)}")

            LOG.info(f"Current -> {root}")
            if self.live_status:
                self.live_status.update(f":mag: Scanning {root}")

            # Stop descending into directories if the maximum depth is reached
            if max_deep is not None and current_depth > max_deep:
                # Don't go deeper
                del dirs[:]

            # Filter filenames based on exclusion criteria
            filenames[:] = [
                f
                for f in filenames
                if not should_exclude(excludes=self.exclude_files, to_analyze=Path(f))
            ]

            self.file_count += len(filenames)

            for file_name in filenames:
                for handler in self.handlers:
                    file_type = handler.can_handle(root, file_name, self.include_files)
                    if file_type:
                        inspectable_file: Path = Path(root, file_name)
                        if file_type.value not in files or not files[file_type.value]:
                            files[file_type.value] = set()
                        files[file_type.value].add(inspectable_file)
                        break
            level += 1

        return dir_path, files

    def search(self) -> Tuple[str, Dict[str, Set[Path]]]:
        """
        Initiates the search for files within the target directory.

        Returns:
            Tuple[str, Dict[str, Set[Path]]]: The target directory and a dictionary of file types and their corresponding paths.
        """
        return self.process_directory(self.target, self.max_level)
