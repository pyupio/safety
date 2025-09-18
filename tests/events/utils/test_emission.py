"""
Tests for event emission utilities.
"""

import pytest
import uuid
from unittest.mock import MagicMock, patch

from safety_schemas.models.events import EventType
from safety.events.utils.emission import emit_diff_operations
from safety.tool.environment_diff import PackageLocation
from safety_schemas.models.events.types import ToolType


@pytest.mark.unit
class TestEmitDiffOperations:
    """
    Test suite for emit_diff_operations function.
    """

    def setup_method(self):
        """
        Set up test fixtures.
        """
        self.event_bus = MagicMock()
        self.ctx = MagicMock()
        self.ctx.obj = MagicMock()
        self.ctx.obj.correlation_id = str(uuid.uuid4())

    @pytest.mark.parametrize(
        "added, removed, updated, tool_path, expected_calls",
        [
            (
                {
                    PackageLocation(
                        name="requests",
                        location="/usr/local/lib/python3.9/site-packages",
                    ): "2.28.1",
                    PackageLocation(
                        name="urllib3",
                        location="/home/user/.local/lib/python3.9/site-packages",
                    ): "1.26.12",
                },
                {
                    PackageLocation(
                        name="old-package", location="/usr/lib/python3.9/site-packages"
                    ): "1.0.0"
                },
                {
                    PackageLocation(
                        name="numpy", location="/usr/local/lib/python3.9/site-packages"
                    ): ("1.21.0", "1.23.5")
                },
                "/usr/bin/pip",
                4,
            ),
            (
                {
                    PackageLocation(
                        name="requests", location="C:\\Python39\\Lib\\site-packages"
                    ): "2.28.1"
                },
                {
                    PackageLocation(
                        name="old-pkg",
                        location="C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python39\\Lib\\site-packages",
                    ): "1.0.0"
                },
                {
                    PackageLocation(
                        name="numpy", location="C:\\Python39\\Lib\\site-packages"
                    ): ("1.21.0", "1.23.5")
                },
                "C:\\Python39\\Scripts\\pip.exe",
                3,
            ),
        ],
    )
    def test_emit_diff_operations_with_multiple_operations(
        self, added, removed, updated, tool_path, expected_calls
    ):
        """
        The emit_diff_operations function should emit the correct number of events
        based on the number of added, removed, and updated packages.
        """
        by_tool = ToolType.PIP

        emit_diff_operations(
            self.event_bus,
            self.ctx,
            added=added,
            removed=removed,
            updated=updated,
            tool_path=tool_path,
            by_tool=by_tool,
        )

        # Basic count and common payload assertions
        assert self.event_bus.emit.call_count == expected_calls

        # Group events by type (order is not guaranteed)
        installed_events = []
        uninstalled_events = []
        updated_events = []

        for call in self.event_bus.emit.call_args_list:
            event = call[0][0]
            assert event.payload.tool == by_tool
            assert event.payload.tool_path == tool_path

            if event.type == EventType.PACKAGE_INSTALLED:
                installed_events.append(event)
            elif event.type == EventType.PACKAGE_UNINSTALLED:
                uninstalled_events.append(event)
            elif event.type == EventType.PACKAGE_UPDATED:
                updated_events.append(event)

        # Assert counts by type
        assert len(installed_events) == len(added)
        assert len(uninstalled_events) == len(removed)
        assert len(updated_events) == len(updated)

        # Validate payload fields for installed events
        expected_installed = {(pl.name, v, pl.location) for pl, v in added.items()}
        observed_installed = {
            (e.payload.package_name, e.payload.version, e.payload.location)
            for e in installed_events
        }
        assert observed_installed == expected_installed

        # Validate payload fields for uninstalled events
        expected_uninstalled = {(pl.name, v, pl.location) for pl, v in removed.items()}
        observed_uninstalled = {
            (e.payload.package_name, e.payload.version, e.payload.location)
            for e in uninstalled_events
        }
        assert observed_uninstalled == expected_uninstalled

        # Validate payload fields for updated events (including tuple order)
        expected_updated = {
            (pl.name, pl.location, pv, cv) for pl, (pv, cv) in updated.items()
        }
        observed_updated = {
            (
                e.payload.package_name,
                e.payload.location,
                e.payload.previous_version,
                e.payload.current_version,
            )
            for e in updated_events
        }
        assert observed_updated == expected_updated

    def test_emit_diff_operations_with_empty_locations(self):
        """
        Test emit_diff_operations with empty or None locations.
        """
        # Arrange
        added = {
            PackageLocation(name="pkg-no-location", location=""): "1.0.0",
            PackageLocation(name="pkg-none-location", location=None or ""): "2.0.0",
        }
        removed = {}
        updated = {}
        tool_path = "/usr/bin/pip"
        by_tool = ToolType.PIP

        # Act
        emit_diff_operations(
            self.event_bus,
            self.ctx,
            added=added,
            removed=removed,
            updated=updated,
            tool_path=tool_path,
            by_tool=by_tool,
        )

        # Assert - Should still emit events with empty locations
        assert self.event_bus.emit.call_count == 2

        # Verify events are emitted for packages with empty locations
        for call in self.event_bus.emit.call_args_list:
            event = call[0][0]
            assert event.payload.location == ""
            assert event.payload.tool == by_tool
            assert event.type == EventType.PACKAGE_INSTALLED

    def test_emit_diff_operations_without_correlation_id(self):
        """
        Test emit_diff_operations generates correlation_id when not present.
        """
        # Arrange
        self.ctx.obj.correlation_id = None
        added = {
            PackageLocation(
                name="test-pkg", location="/usr/local/lib/python3.9/site-packages"
            ): "1.0.0"
        }
        removed = {}
        updated = {}
        tool_path = "/usr/bin/pip"
        by_tool = ToolType.PIP

        # Act
        with patch(
            "uuid.uuid4", return_value=uuid.UUID("12345678-1234-5678-1234-567812345678")
        ):
            emit_diff_operations(
                self.event_bus,
                self.ctx,
                added=added,
                removed=removed,
                updated=updated,
                tool_path=tool_path,
                by_tool=by_tool,
            )

        # Assert - Should generate and assign correlation ID
        assert self.ctx.obj.correlation_id == "12345678-1234-5678-1234-567812345678"

    @pytest.mark.parametrize(
        "preset_id, expected_id",
        [
            ("preset-id", "preset-id"),
            (None, "12345678-1234-5678-1234-567812345678"),
        ],
    )
    def test_emit_diff_operations_correlation_id_propagation(
        self, preset_id, expected_id
    ):
        """
        Events should carry the existing correlation_id if preset; otherwise a new one is generated
        and attached to the context and emitted events.
        """
        # Arrange
        self.ctx.obj.correlation_id = preset_id
        added = {PackageLocation(name="pkg", location="/site-packages"): "1.0.0"}

        if preset_id is None:
            uuid_patch = patch(
                "uuid.uuid4",
                return_value=uuid.UUID("12345678-1234-5678-1234-567812345678"),
            )
        else:
            uuid_patch = patch("uuid.uuid4")  # no-op

        with uuid_patch:
            emit_diff_operations(
                self.event_bus,
                self.ctx,
                added=added,
                removed={},
                updated={},
                tool_path="/usr/bin/pip",
                by_tool=ToolType.PIP,
            )

        # Assert every emitted event has the expected correlation id
        assert self.ctx.obj.correlation_id == expected_id
        for call in self.event_bus.emit.call_args_list:
            event = call[0][0]
            assert event.correlation_id == expected_id

    def test_emit_diff_operations_with_no_changes(self):
        """
        Test emit_diff_operations with no package changes.
        """
        # Arrange
        added = {}
        removed = {}
        updated = {}
        tool_path = "/usr/bin/pip"
        by_tool = ToolType.PIP

        # Act
        emit_diff_operations(
            self.event_bus,
            self.ctx,
            added=added,
            removed=removed,
            updated=updated,
            tool_path=tool_path,
            by_tool=by_tool,
        )

        # Assert - Should not emit any events for empty changes
        self.event_bus.emit.assert_not_called()

    @pytest.mark.parametrize(
        "tool_type, tool_path",
        [
            (ToolType.PIP, "/usr/bin/pip"),
            (ToolType.POETRY, "/usr/local/bin/poetry"),
            (ToolType.UV, "/home/user/.cargo/bin/uv"),
        ],
    )
    def test_emit_diff_operations_with_different_tools(self, tool_type, tool_path):
        """
        Test emit_diff_operations with different tool types.
        """
        # Arrange
        added = {
            PackageLocation(
                name="test-pkg", location="/usr/local/lib/python3.9/site-packages"
            ): "1.0.0"
        }

        # Act
        emit_diff_operations(
            self.event_bus,
            self.ctx,
            added=added,
            removed={},
            updated={},
            tool_path=tool_path,
            by_tool=tool_type,
        )

        # Assert - Tool type should be correctly set
        assert self.event_bus.emit.call_count == 1
        package_event = self.event_bus.emit.call_args_list[0][0][0]
        assert package_event.payload.tool_path == tool_path
        assert package_event.payload.tool == tool_type

    def test_emit_diff_operations_creates_correct_payload_structure(self):
        """
        Test that emit_diff_operations creates events with correct payload structure.
        """
        # Arrange
        package_loc = PackageLocation(
            name="test-pkg", location="/usr/local/lib/python3.9/site-packages"
        )
        added = {package_loc: "1.0.0"}
        tool_path = "/usr/bin/pip"
        by_tool = ToolType.PIP

        # Act
        emit_diff_operations(
            self.event_bus,
            self.ctx,
            added=added,
            removed={},
            updated={},
            tool_path=tool_path,
            by_tool=by_tool,
        )

        # Assert - Check the event was emitted with correct structure
        assert self.event_bus.emit.call_count == 1
        event_call = self.event_bus.emit.call_args_list[0]
        event = event_call[0][0]

        # Check event type and payload structure
        assert event.type == EventType.PACKAGE_INSTALLED
        assert event.payload.package_name == "test-pkg"
        assert event.payload.version == "1.0.0"
        assert event.payload.location == "/usr/local/lib/python3.9/site-packages"
        assert event.payload.tool_path == tool_path
        assert event.payload.tool == by_tool
