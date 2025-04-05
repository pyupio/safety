import sys


def apply_asyncio_patch():
    """
    Apply a patch to asyncio's proactor events on Windows when running Python 3.8 or 3.9.

    This patch is needed because of a bug in Python 3.8 and 3.9 that causes a
    RuntimeError to be raised when the event loop is closed while there are still
    open file descriptors. This bug was fixed in Python 3.10.

    The bug manifests itself when using the proactor event loop on Windows, which
    is the default event loop on Windows. The bug causes the event loop to be
    closed while there are still open file descriptors, which causes a RuntimeError
    to be raised.

    This patch catches the RuntimeError and ignores it, which allows the event loop
    to be closed properly.

    See https://bugs.python.org/issue39232 and https://github.com/python/cpython/issues/92841
    for more information.
    """

    if sys.platform == "win32" and (3, 8, 0) <= sys.version_info < (3, 11, 0):
        import asyncio.proactor_events as proactor_events

        original_del = proactor_events._ProactorBasePipeTransport.__del__

        def patched_del(self):
            try:
                original_del(self)
            except RuntimeError as e:
                if str(e) != "Event loop is closed":
                    raise

        proactor_events._ProactorBasePipeTransport.__del__ = patched_del


apply_asyncio_patch()
