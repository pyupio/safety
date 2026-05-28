from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, List, Optional, TypeVar, cast, overload


if TYPE_CHECKING:
    from safety.events.event_bus import EventBus
    from safety.cli_util import CustomContext


def should_emit(
    event_bus: Optional["EventBus"], ctx: Optional["CustomContext"]
) -> bool:
    """
    Common conditions that apply to all event emissions.
    """
    if event_bus is None:
        return False

    # Be aware that ctx depends on the command being parsed, if the emit func
    # is called from the entrypoint group command, ctx will not have
    # the command parsed yet.

    return True


def should_emit_firewall_heartbeat(ctx: Optional["CustomContext"]) -> bool:
    """
    Condition to check if the firewall is enabled.
    """
    if ctx and ctx.obj.firewall_enabled:
        return True

    return False


# Define TypeVars for better typing
F = TypeVar("F", bound=Callable[..., Any])
R = TypeVar("R")


@overload
def conditional_emitter(emit_func: F, *, conditions: None = None) -> F: ...


@overload
def conditional_emitter(
    emit_func: None = None,
    *,
    conditions: Optional[List[Callable[[Optional["CustomContext"]], bool]]] = None,
) -> Callable[[F], F]: ...


def conditional_emitter(
    emit_func=None,
    *,
    conditions: Optional[List[Callable[[Optional["CustomContext"]], bool]]] = None,
):
    """
    A decorator that conditionally calls the decorated function based on conditions.
    Only executes the decorated function if all conditions evaluate to True.
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(event_bus, ctx=None, *args, **kwargs):
            if not should_emit(event_bus, ctx):
                return None

            if conditions:
                if all(condition(ctx) for condition in conditions):
                    return func(event_bus, ctx, *args, **kwargs)
                return None
            return func(event_bus, ctx, *args, **kwargs)

        return cast(F, wrapper)  # Cast to help type checker

    if emit_func is None:
        return decorator
    return decorator(emit_func)
