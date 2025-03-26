# Standard library imports
import logging
import sys
import traceback
from functools import wraps
from typing import TYPE_CHECKING, Optional

# Third-party imports
import click

# Local imports
from safety.constants import EXIT_CODE_FAILURE, EXIT_CODE_OK
from safety.errors import SafetyError, SafetyException

from safety.events.utils import emit_command_error

if TYPE_CHECKING:
    from safety.scan.models import ScanOutput


LOG = logging.getLogger(__name__)


def output_exception(exception: Exception, exit_code_output: bool = True) -> None:
    """
    Output an exception message to the console and exit.

    Args:
        exception (Exception): The exception to output.
        exit_code_output (bool): Whether to output the exit code.

    Exits:
        Exits the program with the appropriate exit code.
    """
    click.secho(str(exception), fg="red", file=sys.stderr)

    if exit_code_output:
        exit_code = EXIT_CODE_FAILURE
        if hasattr(exception, "get_exit_code"):
            exit_code = exception.get_exit_code()
    else:
        exit_code = EXIT_CODE_OK

    sys.exit(exit_code)


def handle_cmd_exception(func):
    """
    Decorator to handle exceptions in command functions.

    Args:
        func: The command function to wrap.

    Returns:
        The wrapped function.
    """

    @wraps(func)
    def inner(ctx, output: Optional["ScanOutput"] = None, *args, **kwargs):
        if output:
            from safety.scan.models import ScanOutput

            kwargs.update({"output": output})

            if output is ScanOutput.NONE:
                return func(ctx, *args, **kwargs)

        try:
            return func(ctx, *args, **kwargs)
        except click.ClickException as e:
            emit_command_error(
                ctx.obj.event_bus, ctx, message=str(e), traceback=traceback.format_exc()
            )
            raise e
        except SafetyError as e:
            LOG.exception("Expected SafetyError happened: %s", e)
            emit_command_error(
                ctx.obj.event_bus, ctx, message=str(e), traceback=traceback.format_exc()
            )
            output_exception(e, exit_code_output=True)
        except Exception as e:
            emit_command_error(
                ctx.obj.event_bus, ctx, message=str(e), traceback=traceback.format_exc()
            )
            LOG.exception("Unexpected Exception happened: %s", e)
            exception = e if isinstance(e, SafetyException) else SafetyException(info=e)
            output_exception(exception, exit_code_output=True)

    return inner
