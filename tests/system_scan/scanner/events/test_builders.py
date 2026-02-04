import pytest
import json
import re
from unittest.mock import Mock

from safety.system_scan.scanner.events.builders import (
    build_discovered_event,
    build_system_scan_event,
    SystemScanAction,
    build_event,
)


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_detection():
    detection = Mock()
    detection.kind.value = "dependency"
    detection.get_payload.return_value = {
        "subtype": "python:pypi",
        "package": "requests",
        "version": "2.28.1",
    }
    return detection


@pytest.fixture
def sample_system_scan_id():
    return "scan-test-12345"


def test_build_event_time_format_rfc3339():
    event = build_event("test.type", {"key": "value"}, {"ext": "data"})
    time_str = event["time"]

    rfc3339_pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$"
    assert re.match(rfc3339_pattern, time_str), (
        f"Invalid RFC 3339 time format: {time_str}"
    )


def test_build_event_has_unique_id():
    event1 = build_event("test.type", {}, {})
    event2 = build_event("test.type", {}, {})
    event3 = build_event("test.type", {}, {})

    ids = [event1["id"], event2["id"], event3["id"]]
    assert len(set(ids)) == 3, "Event IDs must be unique"


def test_build_event_structure():
    event_type = "com.test.event"
    data = {"key": "value"}
    extensions = {"ext1": "val1", "ext2": "val2"}
    source = "urn:test:source"

    event = build_event(event_type, data, extensions, source)

    assert event["specversion"] == "1.0"
    assert event["type"] == event_type
    assert event["data"] == data
    assert event["source"] == source
    assert event["datacontenttype"] == "application/json"
    assert event["ext1"] == "val1"
    assert event["ext2"] == "val2"
    assert "id" in event
    assert "time" in event


def test_build_discovered_event_uses_payload_as_data(
    mock_detection, sample_system_scan_id
):
    expected_payload = {"test": "data", "version": "1.0.0"}
    mock_detection.get_payload.return_value = expected_payload

    event = build_discovered_event(mock_detection, sample_system_scan_id)
    mock_detection.get_payload.assert_called_once()

    assert event["data"] == expected_payload


@pytest.mark.parametrize(
    "event_builder,args",
    [
        (build_discovered_event, "mock_detection,sample_system_scan_id"),
        (build_system_scan_event, "sample_system_scan_id,SystemScanAction.SUCCEEDED"),
    ],
)
def test_cloudevent_compliance(request, event_builder, args):
    arg_names = args.split(",")
    resolved_args = []
    for arg_name in arg_names:
        if arg_name == "mock_detection":
            resolved_args.append(request.getfixturevalue("mock_detection"))
        elif arg_name == "sample_system_scan_id":
            resolved_args.append(request.getfixturevalue("sample_system_scan_id"))
        elif arg_name == "SystemScanAction.SUCCEEDED":
            resolved_args.append(SystemScanAction.SUCCEEDED)

    event = event_builder(*resolved_args)

    required_fields = [
        "specversion",
        "id",
        "source",
        "type",
        "time",
        "datacontenttype",
        "systemscanid",
    ]
    for field in required_fields:
        assert field in event, f"Missing required CloudEvent field: {field}"
        assert event[field] is not None, f"Field {field} cannot be None"
        assert event[field] != "", f"Field {field} cannot be empty"

    assert event["specversion"] == "1.0"
    assert event["source"] == "urn:safetycli:cli:bin"
    assert event["datacontenttype"] == "application/json"


@pytest.mark.parametrize(
    "detection_kind,expected_type",
    [
        ("dependency", "com.safetycli.dependency.discovered"),
        ("vulnerability", "com.safetycli.vulnerability.discovered"),
        ("runtime", "com.safetycli.runtime.discovered"),
        ("environment", "com.safetycli.environment.discovered"),
        ("tool", "com.safetycli.tool.discovered"),
    ],
)
def test_build_discovered_event_all_detection_kinds(
    mock_detection, sample_system_scan_id, detection_kind, expected_type
):
    mock_detection.kind.value = detection_kind

    event = build_discovered_event(mock_detection, sample_system_scan_id)
    assert event["type"] == expected_type


def test_build_discovered_event_detection_get_payload_exception(
    mock_detection, sample_system_scan_id
):
    mock_detection.get_payload.side_effect = ValueError("Payload error")

    with pytest.raises(ValueError, match="Payload error"):
        build_discovered_event(mock_detection, sample_system_scan_id)


def test_build_system_scan_event_generates_correct_event_type(sample_system_scan_id):
    event = build_system_scan_event(sample_system_scan_id, SystemScanAction.SUCCEEDED)
    assert event["type"] == "com.safetycli.system_scan.succeeded"


def test_build_system_scan_event_has_empty_data(sample_system_scan_id):
    event = build_system_scan_event(sample_system_scan_id, SystemScanAction.SUCCEEDED)
    assert event["data"] == {}


def test_helpers_produce_json_serializable_output(
    mock_detection, sample_system_scan_id
):
    discovered_event = build_discovered_event(mock_detection, sample_system_scan_id)
    system_scan_event = build_system_scan_event(
        sample_system_scan_id, SystemScanAction.SUCCEEDED
    )

    # Should not raise exceptions
    json.dumps(discovered_event)
    json.dumps(system_scan_event)


def test_event_ids_unique_across_helpers(mock_detection, sample_system_scan_id):
    discovered_event = build_discovered_event(mock_detection, sample_system_scan_id)
    system_scan_event = build_system_scan_event(
        sample_system_scan_id, SystemScanAction.SUCCEEDED
    )

    assert discovered_event["id"] != system_scan_event["id"]


def test_build_discovered_event_with_complex_payload(
    mock_detection, sample_system_scan_id
):
    complex_payload = {
        "subtype": "python:pypi",
        "package": "requests",
        "version": "2.28.1",
        "dependencies": ["urllib3", "certifi"],
        "metadata": {
            "author": "Kenneth Reitz",
            "license": "Apache 2.0",
            "tags": ["http", "web", "client"],
        },
        "links": [
            {"ref": {"machine_id": "abc123"}, "type": "execution_context"},
            {"ref": {"canonical_path": "/home/user/venv"}, "type": "environment"},
        ],
    }
    mock_detection.get_payload.return_value = complex_payload

    event = build_discovered_event(mock_detection, sample_system_scan_id)
    assert event["data"] == complex_payload
    # Should be JSON serializable
    json.dumps(event)
