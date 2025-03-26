from typing import TYPE_CHECKING, Any, Optional
from typing_extensions import Annotated
from pydantic import ConfigDict
from safety_schemas.models.events import EventTypeBase, PayloadBase


if TYPE_CHECKING:
    pass


class InternalEventType(EventTypeBase):
    """
    Internal event types.
    """

    CLOSE_RESOURCES = "com.safetycli.close_resources"
    FLUSH_SECURITY_TRACES = "com.safetycli.flush_security_traces"
    EVENT_BUS_READY = "com.safetycli.event_bus_ready"


class InternalPayload(PayloadBase):
    ctx: Optional[Annotated[Any, "CustomContext"]] = None

    model_config = ConfigDict(extra="allow")
