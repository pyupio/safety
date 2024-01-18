from abc import ABC, abstractmethod
from pathlib import Path
from types import MappingProxyType
from typing import Dict, List, Optional, Tuple

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

        fetch_database(session=session, full=False, db=False, cached=True,
                       telemetry=True, ecosystem=Ecosystem.PYTHON, 
                       from_cache=False)
                
        fetch_database(session=session, full=True, db=False, cached=True,
                                telemetry=True, ecosystem=Ecosystem.PYTHON, 
                                from_cache=False)


class SafetyProjectFileHandler(FileHandler):
    # Example of a Python File Handler
    
    def __init__(self) -> None:
        super().__init__()
        self.ecosystem = Ecosystem.SAFETY_PROJECT
        
    def download_required_assets(self, session):
        pass
    

ECOSYSTEM_HANDLER_MAPPING = MappingProxyType({
    Ecosystem.PYTHON: PythonFileHandler,
    Ecosystem.SAFETY_PROJECT: SafetyProjectFileHandler,
})
