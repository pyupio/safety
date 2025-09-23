from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set


class ToolIntentionType(Enum):
    """
    High-level intentions that are common across tools
    """

    ADD_PACKAGE = auto()
    REMOVE_PACKAGE = auto()
    UPDATE_PACKAGE = auto()
    DOWNLOAD_PACKAGE = auto()
    SEARCH_PACKAGES = auto()
    SYNC_PACKAGES = auto()
    LIST_PACKAGES = auto()
    INIT_PROJECT = auto()
    BUILD_PROJECT = auto()
    RUN_SCRIPT = auto()
    UNKNOWN = auto()


@dataclass
class Dependency:
    """
    Common representation of a dependency
    """

    name: str
    arg_index: int
    original_text: str
    version_constraint: Optional[str] = None
    extras: Set[str] = field(default_factory=set)
    is_dev_dependency: bool = False
    corrected_text: Optional[str] = None


@dataclass
class CommandToolIntention:
    """
    Represents a parsed tool command with normalized intention
    """

    tool: str
    command: str
    intention_type: ToolIntentionType
    command_chain: List[str] = field(default_factory=list)
    packages: List[Dependency] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    raw_args: List[str] = field(default_factory=list)

    def modifies_packages(self) -> bool:
        """
        Check if this intention type modifies installed packages.
        """
        return self.intention_type in {
            ToolIntentionType.ADD_PACKAGE,
            ToolIntentionType.REMOVE_PACKAGE,
            ToolIntentionType.UPDATE_PACKAGE,
            ToolIntentionType.SYNC_PACKAGES,
        }

    def queries_packages(self) -> bool:
        """
        Check if this intention type queries for packages.
        """
        return self.intention_type in {
            ToolIntentionType.SEARCH_PACKAGES,
            ToolIntentionType.LIST_PACKAGES,
        }
