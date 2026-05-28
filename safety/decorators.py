from functools import wraps

from safety.events.utils import emit_command_executed


def notify(func):
    """
    A decorator that wraps a function to emit events.

    Args:
      func (callable): The function to be wrapped by the decorator.

    Returns:
      callable: The wrapped function with notification logic.

    The decorator ensures that the `emit_command_executed` function is called
    after the wrapped function completes, regardless of whether it exits
    normally or via a `SystemExit` exception.

    Example:
      @notify
      def my_function(ctx, *args, **kwargs):
      # function implementation
      pass
    """

    @wraps(func)
    def inner(ctx, *args, **kwargs):
        try:
            result = func(ctx, *args, **kwargs)
            emit_command_executed(ctx.obj.event_bus, ctx, returned_code=0)
            return result
        except SystemExit as e:
            # Handle sys.exit() case
            exit_code = e.code if isinstance(e.code, int) else 1
            emit_command_executed(ctx.obj.event_bus, ctx, returned_code=exit_code)
            raise
        # Any other exceptions will bypass notification and propagate normally

    return inner
