from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from enum import Enum
from .filesystem import FsRuntime
from dataclasses import asdict


class DetectionKind(Enum):
    EXECUTION_CONTEXT = "execution_context"
    RUNTIME = "runtime"
    ENVIRONMENT = "environment"
    DEPENDENCY = "dependency"
    TOOL = "tool"


@dataclass
class Candidate:
    """
    A filesystem path that might contain entities of interest.
    """

    path: Path
    source: str  # "PATH", "HOME", "KNOWN_PATHS"
    hint: str
    depth: int = 0


def _meta_serialization_factory(items):
    """
    Serializes meta data for detections.
    """
    result = {}

    for k, v in items:
        result[k] = (
            str(v) if isinstance(v, Path) else (v.value if isinstance(v, Enum) else v)
        )
    return result


@dataclass
class Detection:
    """
    A detected entity of interest.
    """

    kind: DetectionKind
    subtype: str
    stable_id: str
    primary_path: str
    scope: str
    found_via: list[str] = field(default_factory=list)
    meta: Any = field(default_factory=dict)

    def get_payload(self) -> dict[str, Any]:
        """
        Serializes the metadata collected about the detection.
        This method is used to generate the CloudEvent data object.

        Returns:
            dict[str, Any]: The serialized metadata.
        """
        meta_asdict = asdict(self.meta, dict_factory=_meta_serialization_factory)
        payload: dict[str, Any] = {
            "type": self.kind.value,
            "subtype": self.subtype,
        } | meta_asdict

        # Links need to be an array of objects
        if "links" in meta_asdict:
            payload["links"] = self.meta.links.to_list() if self.meta.links else []

        return payload

    def to_dict(self) -> dict[str, Any]:
        data = {
            "kind": self.kind.value,
            "subtype": self.subtype,
            "stable_id": self.stable_id,
            "primary_path": self.primary_path,
            "scope": self.scope,
            "found_via": self.found_via,
            "meta": self.get_payload(),
        }

        return data


@dataclass
class FileIntegrity:
    sha256: str | None
    size_bytes: int
    mtime: float
    ctime: float
    inode: int | None
    device: int | None

    @classmethod
    def from_path(cls, path: Path, fs: FsRuntime) -> FileIntegrity:
        stat = fs.stat(path)

        return cls(
            sha256=fs.sha256(path),
            size_bytes=stat.st_size,
            mtime=stat.st_mtime,
            ctime=stat.st_ctime,
            inode=stat.st_ino,
            device=stat.st_dev,
        )
