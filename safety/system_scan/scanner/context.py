from dataclasses import dataclass, field

from .events.payloads.links import ExecutionContextRelation
from .registry import ScanRefRegistry
from .callbacks import Callbacks
from .filesystem import FsRuntime


@dataclass
class Config:
    """
    System scan configuration.
    """

    max_depth: int = 5
    prune_dirs: list[str] = field(
        default_factory=lambda: [
            ".git",
            "node_modules",
            ".cache",
            "__pycache__",
            ".npm",
            ".yarn",
            ".cargo",
            ".rustup",
        ]
    )


@dataclass(frozen=True)
class DetectContext:
    exec_ctx_rel: ExecutionContextRelation
    registry: ScanRefRegistry
    callbacks: Callbacks
    config: Config
    fs: FsRuntime
