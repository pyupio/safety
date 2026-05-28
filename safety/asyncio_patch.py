import sys
import logging


logger = logging.getLogger(__name__)


def apply_asyncio_patch():
    """
    Apply a patch to asyncio's exception handling for subprocesses.

    There are some issues with asyncio's exception handling for subprocesses,
    which causes a RuntimeError to be raised when the event loop was already closed.

    This patch catches the RuntimeError and ignores it, which allows the event loop
    to be closed properly.

    Similar issues:
    - https://bugs.python.org/issue39232
    - https://github.com/python/cpython/issues/92841
    """

    import asyncio.base_subprocess

    original_subprocess_del = asyncio.base_subprocess.BaseSubprocessTransport.__del__

    def patched_subprocess_del(self):
        try:
            original_subprocess_del(self)
        except (RuntimeError, ValueError, OSError) as e:
            if isinstance(e, RuntimeError) and str(e) != "Event loop is closed":
                raise
            if isinstance(e, ValueError) and str(e) != "I/O operation on closed pipe":
                raise
            if isinstance(e, OSError) and "[WinError 6]" not in str(e):
                raise
            logger.debug(f"Patched {original_subprocess_del}")

    asyncio.base_subprocess.BaseSubprocessTransport.__del__ = patched_subprocess_del

    if sys.platform == "win32":
        import asyncio.proactor_events as proactor_events

        original_pipe_del = proactor_events._ProactorBasePipeTransport.__del__

        def patched_pipe_del(self):
            try:
                original_pipe_del(self)
            except (RuntimeError, ValueError) as e:
                if isinstance(e, RuntimeError) and str(e) != "Event loop is closed":
                    raise
                if (
                    isinstance(e, ValueError)
                    and str(e) != "I/O operation on closed pipe"
                ):
                    raise
                logger.debug(f"Patched {original_pipe_del}")

        original_repr = proactor_events._ProactorBasePipeTransport.__repr__

        def patched_repr(self):
            try:
                return original_repr(self)
            except ValueError as e:
                if str(e) != "I/O operation on closed pipe":
                    raise
                logger.debug(f"Patched {original_repr}")
                return f"<{self.__class__} [closed]>"

        proactor_events._ProactorBasePipeTransport.__del__ = patched_pipe_del
        proactor_events._ProactorBasePipeTransport.__repr__ = patched_repr

        import subprocess

        original_popen_del = subprocess.Popen.__del__

        def patched_popen_del(self):
            try:
                original_popen_del(self)
            except OSError as e:
                if "[WinError 6]" not in str(e):
                    raise
                logger.debug(f"Patched {original_popen_del}")

        subprocess.Popen.__del__ = patched_popen_del


apply_asyncio_patch()
