import logging
import re
import shutil
import subprocess
import sys
import time
from typing import (
    TYPE_CHECKING,
    Dict,
    List,
    Optional,
    Tuple,
)
import uuid

from safety_schemas.models.events import EventType
from safety_schemas.models.events.types import ToolType
from safety_schemas.models.events.payloads import (
    FirewallConfiguredPayload,
    FirewallDisabledPayload,
    PackageInstalledPayload,
    PackageUninstalledPayload,
    PackageUpdatedPayload,
    CommandExecutedPayload,
    ToolCommandExecutedPayload,
    CommandErrorPayload,
    AliasConfig,
    IndexConfig,
    ToolStatus,
    CommandParam,
    ProcessStatus,
    FirewallHeartbeatPayload,
)

from ..event_bus import EventBus

from .creation import (
    create_event,
)
from .data import (
    clean_parameter,
    get_command_path,
    get_root_context,
    scrub_sensitive_value,
    translate_param_source,
)
from .conditions import conditional_emitter, should_emit_firewall_heartbeat


if TYPE_CHECKING:
    from safety.models import SafetyCLI, ToolResult
    from safety.cli_util import CustomContext

logger = logging.getLogger(__name__)


@conditional_emitter(conditions=[should_emit_firewall_heartbeat])
def emit_firewall_heartbeat(
    event_bus: "EventBus", ctx: Optional["CustomContext"], *, tools: List[ToolStatus]
):
    payload = FirewallHeartbeatPayload(tools=tools)
    event = create_event(payload=payload, event_type=EventType.FIREWALL_HEARTBEAT)

    event_bus.emit(event)


@conditional_emitter
def emit_firewall_disabled(
    event_bus: "EventBus",
    ctx: Optional["CustomContext"] = None,
    *,
    reason: Optional[str],
):
    payload = FirewallDisabledPayload(reason=reason)
    event = create_event(payload=payload, event_type=EventType.FIREWALL_DISABLED)

    event_bus.emit(event)


@conditional_emitter
def emit_firewall_configured(
    event_bus: "EventBus",
    ctx: Optional["CustomContext"] = None,
    *,
    alias_config: AliasConfig,
    index_config: IndexConfig,
):
    PIP_TOOL = "pip"
    command_path = shutil.which(PIP_TOOL)
    reachable = False
    version = "unknown"

    if command_path:
        args = [command_path, "--version"]
        result = subprocess.run(args, capture_output=True, text=True)

        if result.returncode == 0:
            output = result.stdout
            reachable = True

            # Extract version
            version_match = re.search(r"pip (\d+\.\d+(?:\.\d+)?)", output)
            if version_match:
                version = version_match.group(1)
    else:
        command_path = PIP_TOOL

    tool = ToolStatus(
        type=ToolType.PIP,
        command_path=command_path,
        version=version,
        reachable=reachable,
        alias_config=alias_config,
        index_config=index_config,
    )

    payload = FirewallConfiguredPayload(tools=[tool])

    event = create_event(payload=payload, event_type=EventType.FIREWALL_CONFIGURED)

    event_bus.emit(event)


@conditional_emitter
def emit_diff_operations(
    event_bus: "EventBus",
    ctx: "CustomContext",
    *,
    added: Dict[str, str],
    removed: Dict[str, str],
    updated: Dict[str, Tuple[str, str]],
    by_tool: ToolType,
):
    obj: "SafetyCLI" = ctx.obj
    correlation_id = obj.correlation_id

    if (added or removed or updated) and not correlation_id:
        correlation_id = obj.correlation_id = str(uuid.uuid4())

    def emit_package_event(event_bus, correlation_id, payload, event_type):
        event = create_event(
            payload=payload,
            event_type=event_type,
            correlation_id=correlation_id,
        )
        event_bus.emit(event)

    for package_name, version in added.items():
        emit_package_event(
            event_bus,
            correlation_id,
            PackageInstalledPayload(
                package_name=package_name, version=version, tool=by_tool
            ),
            EventType.PACKAGE_INSTALLED,
        )

    for package_name, version in removed.items():
        emit_package_event(
            event_bus,
            correlation_id,
            PackageUninstalledPayload(
                package_name=package_name, version=version, tool=by_tool
            ),
            EventType.PACKAGE_UNINSTALLED,
        )

    for package_name, (previous_version, current_version) in updated.items():
        emit_package_event(
            event_bus,
            correlation_id,
            PackageUpdatedPayload(
                package_name=package_name,
                previous_version=previous_version,
                current_version=current_version,
                tool=by_tool,
            ),
            EventType.PACKAGE_UPDATED,
        )


@conditional_emitter
def emit_tool_command_executed(
    event_bus: "EventBus", ctx: "CustomContext", *, tool: ToolType, result: "ToolResult"
) -> None:
    correlation_id = ctx.obj.correlation_id

    if not correlation_id:
        correlation_id = ctx.obj.correlation_id = str(uuid.uuid4())

    process = result.process

    payload = ToolCommandExecutedPayload(
        tool=tool,
        raw_command=[clean_parameter("", arg) for arg in process.args],
        duration_ms=result.duration_ms,
        status=ProcessStatus(
            stdout=process.stdout, stderr=process.stderr, return_code=process.returncode
        ),
    )

    # Scrub after binary coercion to str
    if payload.status.stdout:
        payload.status.stdout = scrub_sensitive_value(payload.status.stdout)
    if payload.status.stderr:
        payload.status.stderr = scrub_sensitive_value(payload.status.stderr)

    event = create_event(
        correlation_id=correlation_id,
        payload=payload,
        event_type=EventType.TOOL_COMMAND_EXECUTED,
    )

    event_bus.emit(event)


@conditional_emitter
def emit_command_executed(
    event_bus: "EventBus", ctx: "CustomContext", *, returned_code: int
) -> None:
    params: List[CommandParam] = []

    root_context = get_root_context(ctx)

    if root_context and hasattr(root_context, "started_at") and root_context.started_at:
        duration_ms = int((time.monotonic() - root_context.started_at) * 1000)
    else:
        duration_ms = 1

    command_name = ctx.command.name
    raw_command = [clean_parameter("", arg) for arg in sys.argv]

    params: List[CommandParam] = []

    for idx, param in enumerate(ctx.command.params):
        param_name = param.name
        param_value = ctx.params.get(param_name)

        # Scrub the parameter value if sensitive
        scrubbed_value = clean_parameter(param_name, param_value)

        # Determine parameter source using Click's API
        click_source = ctx.get_parameter_source(param_name)
        source = translate_param_source(click_source)

        display_name = param_name if param_name else None

        params.append(
            CommandParam(
                position=idx, name=display_name, value=scrubbed_value, source=source
            )
        )

    payload = CommandExecutedPayload(
        command_name=command_name,
        command_path=get_command_path(ctx),
        raw_command=raw_command,
        parameters=params,
        duration_ms=duration_ms,
        status=ProcessStatus(
            return_code=returned_code,
        ),
    )

    event = create_event(
        correlation_id=ctx.obj.correlation_id,
        payload=payload,
        event_type=EventType.COMMAND_EXECUTED,
    )

    try:
        if future := event_bus.emit(event):
            future.result(timeout=0.5)
    except Exception:
        logger.error("Emit Failed %s (%s)", event.type, event.id)


@conditional_emitter
def emit_command_error(
    event_bus: "EventBus",
    ctx: "CustomContext",
    *,
    message: str,
    traceback: Optional[str] = None,
) -> None:
    """
    Emit a CommandErrorEvent with sensitive data scrubbed.
    """
    # Get command name from context if available
    command_name = getattr(ctx, "command", None)
    if command_name and command_name.name:
        command_name = command_name.name

    scrub_traceback = None
    if traceback:
        scrub_traceback = scrub_sensitive_value(traceback)

    command_path = get_command_path(ctx)
    raw_command = [scrub_sensitive_value(arg) for arg in sys.argv]

    payload = CommandErrorPayload(
        command_name=command_name,
        raw_command=raw_command,
        command_path=command_path,
        error_message=scrub_sensitive_value(message),
        stacktrace=scrub_traceback,
    )

    event = create_event(
        payload=payload,
        event_type=EventType.COMMAND_ERROR,
    )

    event_bus.emit(event)
