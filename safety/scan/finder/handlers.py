from abc import ABC, abstractmethod
import os
from pathlib import Path
from types import MappingProxyType
from typing import Dict, List, Optional, Tuple, Set
import toml
from safety_schemas.models import Ecosystem, FileType


NOT_IMPLEMENTED = "You should implement this."

class FileHandler(ABC):

    def __init__(self) -> None:
        self.ecosystem: Optional[Ecosystem] = None

    def can_handle(self, root: str, file_name: str, include_files: Dict[FileType, List[Path]]) -> Optional[FileType]:
        # Keeping it simple for now

        if not self.ecosystem:
            return None

        for f_type in self.ecosystem.file_types:
            if f_type in include_files:
                current = Path(root, file_name).resolve()
                paths = [p.resolve() if p.is_absolute() else (root / p).resolve() for p in include_files[f_type]]
                if current in paths:
                    return f_type

            # Let's compare by name only for now
            # We can put heavier logic here, but for speed reasons,
            # right now is very basic, we will improve this later.
            # Custom matching per File Type
            if file_name.lower().endswith(f_type.value.lower()):
                return f_type

        return None

    @abstractmethod
    def download_required_assets(self, session) -> Dict[str, str]:
        return NotImplementedError(NOT_IMPLEMENTED)


class PythonFileHandler(FileHandler):
    # Example of a Python File Handler

    def __init__(self) -> None:
        super().__init__()
        self.ecosystem = Ecosystem.PYTHON

    def download_required_assets(self, session):
        from safety.safety import fetch_database

        SAFETY_DB_DIR = os.getenv("SAFETY_DB_DIR")

        db = False if SAFETY_DB_DIR is None else SAFETY_DB_DIR


        fetch_database(session=session, full=False, db=db, cached=True,
                       telemetry=True, ecosystem=Ecosystem.PYTHON,
                       from_cache=False)

        fetch_database(session=session, full=True, db=db, cached=True,
                                telemetry=True, ecosystem=Ecosystem.PYTHON,
                                from_cache=False)


class SafetyProjectFileHandler(FileHandler):
    # Example of a Python File Handler

    def __init__(self) -> None:
        super().__init__()
        self.ecosystem = Ecosystem.SAFETY_PROJECT

    def download_required_assets(self, session):
        pass


class PyProjectTomlHandler(FileHandler):
    def __init__(self) -> None:
        super().__init__()
        self.ecosystem = Ecosystem.PYPROJECT_TOML

    def download_required_assets(self, session):
        from safety.safety import fetch_database

        SAFETY_DB_DIR = os.getenv("SAFETY_DB_DIR")

        db = False if SAFETY_DB_DIR is None else SAFETY_DB_DIR


        fetch_database(session=session, full=False, db=db, cached=True,
                       telemetry=True, ecosystem=Ecosystem.PYTHON,
                       from_cache=False)

        fetch_database(session=session, full=True, db=db, cached=True,
                                telemetry=True, ecosystem=Ecosystem.PYTHON,
                                from_cache=False)

    def can_handle(self, root: str, file_name: str, include_files: Dict[FileType, List[Path]]) -> Optional[FileType]:
        if file_name == 'pyproject.toml':
            print("recognized")
            return FileType.PYPROJECT_TOML
        return None

    def handle(self, file_path: Path) -> Set[str]:
        with open(file_path, 'r') as file:
            data = toml.load(file)
            print("printing data", data)
            dependencies = set()

            # Handle 'build-system.requires'
            if 'build-system' in data and 'requires' in data['build-system']:
                dependencies.update(data['build-system']['requires'])

            # Handle 'project.dependencies'
            if 'project' in data and 'dependencies' in data['project']:
                dependencies.update(data['project']['dependencies'])

            # Handle 'tool.poetry.dependencies'
            if 'tool' in data and 'poetry' in data['tool'] and 'dependencies' in data['tool']['poetry']:
                for dep, version in data['tool']['poetry']['dependencies'].items():
                    dependencies.add(f"{dep}=={version}" if isinstance(version, str) else dep)

            return dependencies




ECOSYSTEM_HANDLER_MAPPING = MappingProxyType({
    Ecosystem.PYTHON: PythonFileHandler,
    Ecosystem.SAFETY_PROJECT: SafetyProjectFileHandler,
    Ecosystem.PYPROJECT_TOML: PyProjectTomlHandler,
})
