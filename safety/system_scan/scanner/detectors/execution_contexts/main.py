"""Execution context detection orchestration."""

from __future__ import annotations

from typing import Iterator
from ...models import Detection, DetectionKind
from ...events.payloads import (
    ExecutionContextInfo,
)
from .collectors import get_host_execution_context


class ExecutionContextDetector:
    """
    Detects execution context (host and WSL only).
    This detector should run first to establish the context.
    """

    def __init__(self):
        self.detected = False  # Track if we've already detected context

    def detect(self) -> Iterator[Detection]:
        """
        Detect execution context. This detector doesn't use candidates,
        it runs once to detect the current execution environment.
        """
        # Only detect once per system scan
        if self.detected:
            return

        self.detected = True

        # Always detect host context
        host_context = get_host_execution_context()

        yield self._create_detection(host_context)

        # Detect WSL distributions
        # try:
        #     for wsl_context in collect_wsl_distributions():
        #         yield self._create_detection(wsl_context)
        # except Exception:
        #     # WSL detection failed, continue without it
        #     pass

        # Detect Docker containers.

    def _create_detection(self, context: ExecutionContextInfo) -> Detection:
        """
        Create Detection from execution context dataclass.

        Args:
            context: ExecutionContextInfo dataclass with collected data

        Returns:
            Detection object with execution context information
        """
        subtype = context.subtype.value
        stable_id = f"exec-context:{subtype}:{context.hostname}:{context.machine_id}"

        return Detection(
            kind=DetectionKind.EXECUTION_CONTEXT,
            subtype=subtype,
            stable_id=stable_id,
            primary_path="system",
            scope="system",
            found_via=["SYSTEM_INTROSPECTION"],
            meta=context,  # Store the dataclass directly as meta
        )
