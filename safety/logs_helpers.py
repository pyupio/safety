import functools
import logging


def log_call(*, show_args=True, show_result=False):
    """
    Configurable logging decorator.

    Args:
        show_args: Log function arguments (default: True)
        show_result: Log return value (default: False)
    """

    def decorator(func):
        logger = logging.getLogger(func.__module__)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if logger.isEnabledFor(logging.DEBUG):
                if show_args:
                    args_repr = [repr(a) for a in args]
                    kwargs_repr = [f"{k}={v!r}" for k, v in kwargs.items()]
                    signature = ", ".join(args_repr + kwargs_repr)
                    logger.debug("-> %s(%s)", func.__name__, signature)
                else:
                    logger.debug("-> %s", func.__name__)

            try:
                result = func(*args, **kwargs)

                if logger.isEnabledFor(logging.DEBUG):
                    if show_result:
                        logger.debug("<- %s => %r", func.__name__, result)
                    else:
                        logger.debug("<- %s", func.__name__)

                return result
            except Exception as e:
                logger.error("✗ %s failed: %s", func.__name__, e)
                raise

        return wrapper

    return decorator
