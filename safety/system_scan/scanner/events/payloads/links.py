from __future__ import annotations

from dataclasses import dataclass, field, fields, asdict
from typing import Any


@dataclass(frozen=True)
class HostRef:
    machine_id: str
    hostname: str
    subtype: str = field(default="host", init=False)


ExecutionContextRef = HostRef


@dataclass(frozen=True)
class RuntimeRef:
    canonical_path: str


@dataclass(frozen=True)
class EnvironmentRef:
    canonical_path: str


# Reference Fields


@dataclass(frozen=True)
class ExecutionContextRelation:
    ref: ExecutionContextRef
    type: str = field(default="execution_context", init=False)


@dataclass(frozen=True)
class RuntimeRelation:
    ref: RuntimeRef
    type: str = field(default="runtime", init=False)


@dataclass(frozen=True)
class EnvironmentRelation:
    ref: EnvironmentRef
    type: str = field(default="environment", init=False)


@dataclass(frozen=True)
class ParentEnvironmentRelation:
    ref: EnvironmentRef
    type: str = field(default="parent", init=False)


# Relations Containers - Per entity type


@dataclass
class BaseRelations:
    """
    Base class for entity relationship containers.

    A relationship container is a dataclass that contains a set of relationships
    between entities. For example, a dependency belongs to an environment and an execution context.
    """

    def to_list(self) -> list[dict[str, Any]]:
        """
        Convert entity relationships to list format for event payload generation.

        Iterates through all relationship fields, filtering out None values,
        and converts each relation to a dictionary containing the reference
        and relationship type information.

        Returns:
            list of relationship dictionaries for event payload generation

        Example:
            [
                {"ref": {"machine_id": "abc123"}, "type": "execution_context"},
                {"ref": {"canonical_path": "/usr/bin/python"}, "type": "runtime"}
            ]
        """
        links = []
        for field_obj in fields(self):
            value = getattr(self, field_obj.name)
            if value is not None:
                # Convert Reference object to dict format
                ref_dict = asdict(value)
                links.append(ref_dict)
        return links


@dataclass
class ExecutionContextRelations(BaseRelations):
    pass


@dataclass
class RuntimeRelations(BaseRelations):
    execution_context: ExecutionContextRelation


@dataclass
class EnvironmentRelations(BaseRelations):
    execution_context: ExecutionContextRelation
    runtime: RuntimeRelation | None = None
    parent: ParentEnvironmentRelation | None = None


@dataclass
class DependencyRelations(BaseRelations):
    execution_context: ExecutionContextRelation
    environment: EnvironmentRelation | None = None


# Tool uses same structure as Dependency
ToolRelations = DependencyRelations
