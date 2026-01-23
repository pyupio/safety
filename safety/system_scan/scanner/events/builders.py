from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from ..models import Detection


class DetectionAction(Enum):
    """
    Actions that can be performed on Detection entities.
    """

    DISCOVERED = "discovered"


class SystemScanAction(Enum):
    """
    Actions that represent the state of a system scan.
    """

    SUCCEEDED = "succeeded"
    FAILED = "failed"


def generate_event_id() -> str:
    if sys.version_info >= (3, 14):
        return str(uuid.uuid7())

    return str(uuid.uuid4())


def _get_event_type_from_detection(
    detection: Detection, action: DetectionAction
) -> str:
    return f"com.safetycli.{detection.kind.value}.{action.value}"


def _get_event_type_from_system_scan(action: SystemScanAction) -> str:
    return f"com.safetycli.system_scan.{action.value}"


def _get_extensions_for_system_scan(system_scan_id: str) -> dict[str, str]:
    return {"systemscanid": system_scan_id}


def build_event(
    event_type: str,
    data: dict[str, Any],
    extensions: dict[str, str],
    source: str = "urn:safetycli:cli:bin",
) -> dict[str, Any]:
    """
    Build a CloudEvent v1.0 compliant event dictionary.

    Args:
        event_type: CloudEvent type (e.g., 'com.safetycli.vulnerability.discovered')
        data: Event payload data
        extensions: CloudEvent extensions for additional context
        source: CloudEvent source URI identifying the event producer

    Returns:
        dict containing a CloudEvent v1.0 compliant event
    """

    return {
        "specversion": "1.0",
        "id": generate_event_id(),
        "source": source,
        "type": event_type,
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        **extensions,
        "datacontenttype": "application/json",
        "data": data,
    }


def build_discovered_event(
    detection: Detection,
    system_scan_id: str,
) -> dict[str, Any]:
    """
    Build a CloudEvent for when a detection is discovered during a system scan.

    Args:
        detection: The detection that was discovered
        system_scan_id: Unique identifier for the system scan

    Returns:
        dict containing a CloudEvent v1.0 compliant event
    """
    event_type = _get_event_type_from_detection(
        detection, action=DetectionAction.DISCOVERED
    )
    data = detection.get_payload()

    extensions = _get_extensions_for_system_scan(system_scan_id)

    return build_event(event_type, data, extensions)


def build_system_scan_event(
    system_scan_id: str,
    action: SystemScanAction,
) -> dict[str, Any]:
    """
    Build a CloudEvent for system scan lifecycle events.

    Args:
        system_scan_id: Unique identifier for the system scan
        action: The system scan action/state (e.g., succeeded, failed)

    Returns:
        dict containing a CloudEvent v1.0 compliant event
    """
    event_type = _get_event_type_from_system_scan(action)
    data = {}
    extensions = _get_extensions_for_system_scan(system_scan_id)

    return build_event(event_type, data, extensions)
