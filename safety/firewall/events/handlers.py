from typing import TYPE_CHECKING

from safety.events.handlers import EventHandler
from safety.events.types import EventBusReadyEvent
from safety.events.utils import emit_firewall_heartbeat

from safety.tool import ToolInspector

if TYPE_CHECKING:
    from safety.events.event_bus import EventBus


class HeartbeatInspectionEventHandler(EventHandler[EventBusReadyEvent]):
    """
    Inspect the system for installed tools and send an emit
    a firewall heartbeat event.
    """

    def __init__(self, event_bus: "EventBus") -> None:
        super().__init__()
        self.event_bus = event_bus

    async def handle(self, event: EventBusReadyEvent):
        ctx = event.payload.ctx
        inspector = ToolInspector(timeout=1.0)
        tools = await inspector.inspect_all_tools()

        emit_firewall_heartbeat(self.event_bus, ctx, tools=tools)
