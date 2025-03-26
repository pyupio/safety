from dataclasses import dataclass
from subprocess import CompletedProcess


@dataclass
class ToolResult:
    process: CompletedProcess
    duration_ms: int
