# type: ignore
import unittest
from unittest.mock import MagicMock

from safety_schemas.models.events import EventType
from safety.events.types import InternalEventType
from safety.firewall.events.utils import register_event_handlers
from safety.firewall.events.handlers import HeartbeatInspectionEventHandler
from safety.models.obj import SafetyCLI


class TestFirewallEventsUtils(unittest.TestCase):
    """
    Test cases for firewall events utils functions.
    """

    def setUp(self):
        self.event_bus = MagicMock()
        self.safety_cli = MagicMock(spec=SafetyCLI)
        self.safety_cli.security_events_handler = MagicMock()

    def test_register_event_handlers_with_security_events_handler(self):
        """
        Test register_event_handlers when security_events_handler is available.
        """
        register_event_handlers(self.event_bus, self.safety_cli)

        self.event_bus.subscribe.assert_any_call(
            [InternalEventType.EVENT_BUS_READY],
            self.event_bus.subscribe.call_args_list[0][0][
                1
            ],  # Get the handler from the first call
        )

        self.event_bus.subscribe.assert_any_call(
            [
                EventType.FIREWALL_CONFIGURED,
                EventType.FIREWALL_HEARTBEAT,
                EventType.FIREWALL_DISABLED,
                EventType.PACKAGE_INSTALLED,
                EventType.PACKAGE_UNINSTALLED,
                EventType.PACKAGE_UPDATED,
                EventType.TOOL_COMMAND_EXECUTED,
                EventType.INIT_STARTED,
                EventType.FIREWALL_SETUP_RESPONSE_CREATED,
                EventType.FIREWALL_SETUP_COMPLETED,
                EventType.CODEBASE_DETECTION_STATUS,
                EventType.CODEBASE_SETUP_RESPONSE_CREATED,
                EventType.CODEBASE_SETUP_COMPLETED,
                EventType.INIT_SCAN_COMPLETED,
                EventType.INIT_EXITED,
            ],
            self.safety_cli.security_events_handler,
        )

        self.assertEqual(self.event_bus.subscribe.call_count, 2)

    def test_register_event_handlers_without_security_events_handler(self):
        """
        Test register_event_handlers when security_events_handler is None.
        """
        self.safety_cli.security_events_handler = None

        register_event_handlers(self.event_bus, self.safety_cli)

        self.assertEqual(self.event_bus.subscribe.call_count, 1)

        call_args = self.event_bus.subscribe.call_args
        events_arg = call_args[0][0]
        handler_arg = call_args[0][1]

        self.assertEqual(events_arg, [InternalEventType.EVENT_BUS_READY])
        self.assertIsInstance(handler_arg, HeartbeatInspectionEventHandler)
        self.assertEqual(handler_arg.event_bus, self.event_bus)
