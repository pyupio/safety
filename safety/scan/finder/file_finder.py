
import logging
import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Tuple, Union
from safety_schemas.models import Ecosystem, FileType

from safety.errors import SafetyException

from .handlers import FileHandler, ECOSYSTEM_HANDLER_MAPPING

LOG = logging.getLogger(__name__)

def should_exclude(excludes: Set[Path], to_analyze: Path) -> bool:

    if not to_analyze.is_absolute():
        to_analyze = to_analyze.resolve()

    for exclude in excludes:
        if not exclude.is_absolute():
            exclude = exclude.resolve()

        try:
            if to_analyze == exclude or \
                to_analyze.relative_to(exclude):
                return True
        except ValueError:
            pass
    
    return False


class FileFinder():
    """"
    Defines a common interface to agree in what type of components Safety is trying to
    find depending on the language type.
    """

    def __init__(self, max_level: int, ecosystems: List[Ecosystem], target: Path, 
                 console, live_status=None,
                 exclude: Optional[List[str]] = None, 
                 include_files: Optional[Dict[FileType, List[Path]]] = None,
                 handlers: Optional[Set[FileHandler]] = None) -> None:
        self.max_level = max_level
        self.target = target
        self.include_files = include_files

        if not handlers:
            handlers = set(ECOSYSTEM_HANDLER_MAPPING[ecosystem]() 
                                              for ecosystem in ecosystems)
        
        self.handlers = handlers
        self.file_count = 0
        self.exclude_dirs: Set[Path] = set()
        self.exclude_files: Set[Path] = set()
        exclude = [] if not exclude else exclude

        for pattern in exclude:
            for path in Path(target).glob(pattern):
                if path.is_dir():
                    self.exclude_dirs.add(path)
                else:
                    self.exclude_files.add(path)

        self.console = console
        self.live_status = live_status
    
    def process_directory(self, dir_path, max_deep: Optional[int]=None) -> Tuple[str, Dict[str, Set[Path]]]:
        files: Dict[str, Set[Path]] = {}
        level : int = 0
        initial_depth = len(Path(dir_path).parts) - 1
        skip_dirs = set()
        skip_files = set()

        for root, dirs, filenames in os.walk(dir_path):
            root_path = Path(root)
            current_depth = len(root_path.parts) - initial_depth

            dirs[:] = [d for d in dirs if not should_exclude(excludes=self.exclude_dirs,
                                                             to_analyze=(root_path / Path(d)))]
            
            if dirs:
                LOG.info(f"Directories to inspect -> {', '.join(dirs)}")
            
            LOG.info(f"Current -> {root}")
            if self.live_status:
                self.live_status.update(f":mag: Scanning {root}")

            if max_deep is not None and current_depth > max_deep:
                # Don't go deeper
                del dirs[:]

            filenames[:] = [f for f in filenames if not should_exclude(
                excludes=self.exclude_files, 
                to_analyze=Path(f))]

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
        return self.process_directory(self.target, self.max_level)
