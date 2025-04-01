# type: ignore
import unittest
from unittest.mock import MagicMock, patch

from safety_schemas.models.events import EventType
from safety.events.types import InternalEventType
from safety.events.event_bus.utils import start_event_bus
from safety.models.obj import SafetyCLI


class TestEventBusUtils(unittest.TestCase):
    """
    Test cases for event bus utility functions.
    """

    def setUp(self):
        self.safety_cli = MagicMock(spec=SafetyCLI)
        self.safety_cli.firewall_enabled = False
        self.session = MagicMock()
        self.session.token = {"access_token": "test_token"}
        self.session.proxies = {"http": "proxy_url"}
        self.session.api_key = "test_api_key"

        self.mock_event_bus = MagicMock()

        self.event_bus_patcher = patch("safety.events.event_bus.utils.EventBus")
        self.mock_event_bus_class = self.event_bus_patcher.start()
        self.mock_event_bus_class.return_value = self.mock_event_bus

    def tearDown(self):
        self.event_bus_patcher.stop()

    def test_start_event_bus_without_firewall(self):
        """
        Test start_event_bus when firewall is disabled.
        """
        self.safety_cli.firewall_enabled = False

        start_event_bus(self.safety_cli, self.session)

        self.mock_event_bus.start.assert_called_once()
        self.assertEqual(self.safety_cli.event_bus, self.mock_event_bus)
        self.assertIsNotNone(self.safety_cli.security_events_handler)
        self.mock_event_bus.subscribe.assert_called_once()

        events = self.mock_event_bus.subscribe.call_args[0][0]
        self.assertIn(EventType.COMMAND_EXECUTED, events)
        self.assertIn(EventType.COMMAND_ERROR, events)
        self.assertIn(InternalEventType.CLOSE_RESOURCES, events)
        self.assertIn(InternalEventType.FLUSH_SECURITY_TRACES, events)

        with patch(
            "safety.firewall.events.utils.register_event_handlers"
        ) as mock_register:
            mock_register.assert_not_called()

    @patch("safety.firewall.events.utils.register_event_handlers")
    def test_start_event_bus_with_firewall(self, mock_register_handlers):
        """
        Test start_event_bus when firewall is enabled.
        """
        self.safety_cli.firewall_enabled = True

        start_event_bus(self.safety_cli, self.session)

        self.mock_event_bus.start.assert_called_once()
        self.assertEqual(self.safety_cli.event_bus, self.mock_event_bus)
        self.assertIsNotNone(self.safety_cli.security_events_handler)
        mock_register_handlers.assert_called_once_with(
            self.safety_cli.event_bus, obj=self.safety_cli
        )

    def test_start_event_bus_without_token(self):
        """
        Test start_event_bus when token is not available.
        """
        self.session.token = None
        start_event_bus(self.safety_cli, self.session)
        self.assertIsNotNone(self.safety_cli.security_events_handler)
        self.mock_event_bus.subscribe.assert_called_once()
