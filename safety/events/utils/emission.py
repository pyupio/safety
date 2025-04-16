from concurrent.futures import Future
import logging
from pathlib import Path
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
    Union,
)
import uuid

from safety_schemas.models.events import Event, EventType
from safety_schemas.models.events.types import ToolType
from safety_schemas.models.events.payloads import (
    CodebaseDetectionStatusPayload,
    CodebaseSetupCompletedPayload,
    CodebaseSetupResponseCreatedPayload,
    DependencyFile,
    FirewallConfiguredPayload,
    FirewallDisabledPayload,
    FirewallSetupCompletedPayload,
    FirewallSetupResponseCreatedPayload,
    InitExitStep,
    InitExitedPayload,
    InitScanCompletedPayload,
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
    InitStartedPayload,
    AuthStartedPayload,
    AuthCompletedPayload,
)
import typer

from ..event_bus import EventBus
from ..types.base import InternalEventType, InternalPayload

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
    from safety.init.types import FirewallConfigStatus

logger = logging.getLogger(__name__)


@conditional_emitter
def send_and_flush(event_bus: "EventBus", event: Event) -> Optional[Future]:
    """
    Emit an event and immediately flush the event bus without closing it.

    Args:
        event_bus: The event bus to emit on
        event: The event to emit
    """
    future = event_bus.emit(event)

    # Create and emit flush event
    flush_payload = InternalPayload()
    flush_event = create_event(
        payload=flush_payload, event_type=InternalEventType.FLUSH_SECURITY_TRACES
    )

    # Emit flush event and wait for it to complete
    flush_future = event_bus.emit(flush_event)

    # Wait for both events to complete
    if future:
        try:
            future.result(timeout=0.5)
        except Exception:
            logger.error("Emit Failed %s (%s)", event.type, event.id)

    if flush_future:
        try:
            return flush_future.result(timeout=0.5)
        except Exception:
            logger.error("Flush Failed for event %s", event.id)

    return None


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


def status_to_tool_status(status: "FirewallConfigStatus") -> List[ToolStatus]:
    tools = []
    for tool_type, configs in status.items():
        alias_config = (
            configs["alias"] if isinstance(configs["alias"], AliasConfig) else None
        )
        index_config = (
            configs["index"] if isinstance(configs["index"], IndexConfig) else None
        )

        tool = tool_type.value
        command_path = shutil.which(tool)
        reachable = False
        version = "unknown"

        if command_path:
            args = [command_path, "--version"]
            result = subprocess.run(args, capture_output=True, text=True)

            if result.returncode == 0:
                output = result.stdout
                reachable = True

                # Extract version
                version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", output)
                if version_match:
                    version = version_match.group(1)
        else:
            command_path = tool

        tool = ToolStatus(
            type=tool_type,
            command_path=command_path,
            version=version,
            reachable=reachable,
            alias_config=alias_config,
            index_config=index_config,
        )
        tools.append(tool)

    return tools


@conditional_emitter
def emit_firewall_configured(
    event_bus: "EventBus",
    ctx: Optional["CustomContext"] = None,
    *,
    status: "FirewallConfigStatus",
):
    tools = status_to_tool_status(status)

    payload = FirewallConfiguredPayload(tools=tools)

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
    root_context = get_root_context(ctx)
    NA = ""

    started_at = getattr(root_context, "started_at", None) if root_context else None
    if started_at is not None:
        duration_ms = int((time.monotonic() - started_at) * 1000)
    else:
        duration_ms = 1

    command_name = ctx.command.name if ctx.command.name is not None else NA
    raw_command = [clean_parameter("", arg) for arg in sys.argv]

    params: List[CommandParam] = []

    for idx, param in enumerate(ctx.command.params):
        param_name = param.name if param.name is not None else NA
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


def emit_init_started(
    event_bus: "EventBus", ctx: Union["CustomContext", typer.Context]
) -> None:
    """
    Emit an InitStartedEvent and store it as a pending event in SafetyCLI object.

    Args:
        event_bus: The event bus to emit on
        ctx: The Click context containing the SafetyCLI object
    """
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = InitStartedPayload()
    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.INIT_STARTED,
    )

    if not send_and_flush(event_bus, event):
        # Store as pending event
        obj.pending_events.append(event)


def emit_auth_started(event_bus: "EventBus", ctx: "CustomContext") -> None:
    """
    Emit an AuthStartedEvent and store it as a pending event in SafetyCLI object.

    Args:
        event_bus: The event bus to emit on
        ctx: The Click context containing the SafetyCLI object
    """
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = AuthStartedPayload()
    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.AUTH_STARTED,
    )

    if not send_and_flush(event_bus, event):
        # Store as pending event
        obj.pending_events.append(event)


@conditional_emitter
def emit_auth_completed(
    event_bus: "EventBus",
    ctx: "CustomContext",
    *,
    success: bool = True,
    error_message: Optional[str] = None,
) -> None:
    """
    Emit an AuthCompletedEvent and submit all pending events together.

    Args:
        event_bus: The event bus to emit on
        ctx: The Click context containing the SafetyCLI object
        success: Whether authentication was successful
        error_message: Optional error message if authentication failed
    """
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = AuthCompletedPayload(success=success, error_message=error_message)

    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.AUTH_COMPLETED,
    )

    for pending_event in obj.pending_events:
        event_bus.emit(pending_event)

    obj.pending_events.clear()

    # Emit auth completed event and flush
    send_and_flush(event_bus, event)


@conditional_emitter
def emit_firewall_setup_response_created(
    event_bus: "EventBus",
    ctx: Union["CustomContext", typer.Context],
    *,
    user_consent_requested: bool,
    user_consent: Optional[bool] = None,
) -> None:
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = FirewallSetupResponseCreatedPayload(
        user_consent_requested=user_consent_requested, user_consent=user_consent
    )

    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.FIREWALL_SETUP_RESPONSE_CREATED,
    )

    # Emit and flush
    send_and_flush(event_bus, event)


@conditional_emitter
def emit_codebase_setup_response_created(
    event_bus: "EventBus",
    ctx: Union["CustomContext", typer.Context],
    *,
    user_consent_requested: bool,
    user_consent: Optional[bool] = None,
) -> None:
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = CodebaseSetupResponseCreatedPayload(
        user_consent_requested=user_consent_requested, user_consent=user_consent
    )

    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.CODEBASE_SETUP_RESPONSE_CREATED,
    )

    # Emit and flush
    send_and_flush(event_bus, event)


@conditional_emitter
def emit_codebase_detection_status(
    event_bus: "EventBus",
    ctx: Union["CustomContext", typer.Context],
    *,
    detected: bool,
    detected_files: Optional[List[Path]] = None,
) -> None:
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = CodebaseDetectionStatusPayload(
        detected=detected,
        dependency_files=[
            DependencyFile(file_path=str(file)) for file in detected_files
        ]
        if detected_files
        else None,
    )

    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.CODEBASE_DETECTION_STATUS,
    )

    # Emit and flush
    send_and_flush(event_bus, event)


@conditional_emitter
def emit_init_scan_completed(
    event_bus: "EventBus",
    ctx: Union["CustomContext", typer.Context],
    *,
    scan_id: Optional[str],
) -> None:
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = InitScanCompletedPayload(scan_id=scan_id)

    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.INIT_SCAN_COMPLETED,
    )

    # Emit and flush
    send_and_flush(event_bus, event)


@conditional_emitter
def emit_codebase_setup_completed(
    event_bus: "EventBus",
    ctx: Union["CustomContext", typer.Context],
    *,
    is_created: bool,
    codebase_id: Optional[str] = None,
) -> None:
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = CodebaseSetupCompletedPayload(
        is_created=is_created, codebase_id=codebase_id
    )

    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.CODEBASE_SETUP_COMPLETED,
    )

    # Emit and flush
    send_and_flush(event_bus, event)


@conditional_emitter
def emit_firewall_setup_completed(
    event_bus: "EventBus",
    ctx: "CustomContext",
    *,
    status: "FirewallConfigStatus",
) -> None:
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    tools = status_to_tool_status(status)

    payload = FirewallSetupCompletedPayload(
        tools=tools,
    )

    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.FIREWALL_SETUP_COMPLETED,
    )

    # Emit and flush
    send_and_flush(event_bus, event)


@conditional_emitter
def emit_init_exited(
    event_bus: "EventBus",
    ctx: Union["CustomContext", typer.Context],
    *,
    exit_step: InitExitStep,
) -> None:
    obj: "SafetyCLI" = ctx.obj

    if not obj.correlation_id:
        obj.correlation_id = str(uuid.uuid4())

    payload = InitExitedPayload(exit_step=exit_step)

    event = create_event(
        correlation_id=obj.correlation_id,
        payload=payload,
        event_type=EventType.INIT_EXITED,
    )

    # Emit and flush
    send_and_flush(event_bus, event)
