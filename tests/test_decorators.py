from unittest.mock import MagicMock, patch

import pytest

from safety.decorators import notify


def make_ctx():
    ctx = MagicMock()
    ctx.obj.event_bus = MagicMock()
    return ctx


class TestNotify:
    """
    Tests for the notify decorator in safety/decorators.py.
    """

    def test_success_emits_returned_code_zero_and_returns_value(self):
        ctx = make_ctx()

        @notify
        def my_command(ctx, value, extra=None):
            return (value, extra)

        with patch("safety.decorators.emit_command_executed") as emit:
            result = my_command(ctx, 42, extra="x")

        assert result == (42, "x")
        emit.assert_called_once_with(ctx.obj.event_bus, ctx, returned_code=0)

    def test_success_forwards_args_and_kwargs(self):
        ctx = make_ctx()
        seen = {}

        @notify
        def my_command(ctx, *args, **kwargs):
            seen["args"] = args
            seen["kwargs"] = kwargs

        with patch("safety.decorators.emit_command_executed"):
            my_command(ctx, 1, 2, key="value")

        assert seen["args"] == (1, 2)
        assert seen["kwargs"] == {"key": "value"}

    def test_system_exit_with_int_code_emits_that_code_and_reraises(self):
        ctx = make_ctx()

        @notify
        def my_command(ctx):
            raise SystemExit(3)

        with patch("safety.decorators.emit_command_executed") as emit:
            with pytest.raises(SystemExit) as excinfo:
                my_command(ctx)

        assert excinfo.value.code == 3
        emit.assert_called_once_with(ctx.obj.event_bus, ctx, returned_code=3)

    def test_system_exit_with_zero_code_emits_zero(self):
        ctx = make_ctx()

        @notify
        def my_command(ctx):
            raise SystemExit(0)

        with patch("safety.decorators.emit_command_executed") as emit:
            with pytest.raises(SystemExit):
                my_command(ctx)

        emit.assert_called_once_with(ctx.obj.event_bus, ctx, returned_code=0)

    def test_system_exit_with_no_code_emits_one(self):
        ctx = make_ctx()

        @notify
        def my_command(ctx):
            raise SystemExit()

        with patch("safety.decorators.emit_command_executed") as emit:
            with pytest.raises(SystemExit) as excinfo:
                my_command(ctx)

        assert excinfo.value.code is None
        emit.assert_called_once_with(ctx.obj.event_bus, ctx, returned_code=1)

    def test_system_exit_with_string_code_emits_one(self):
        ctx = make_ctx()

        @notify
        def my_command(ctx):
            raise SystemExit("something went wrong")

        with patch("safety.decorators.emit_command_executed") as emit:
            with pytest.raises(SystemExit):
                my_command(ctx)

        emit.assert_called_once_with(ctx.obj.event_bus, ctx, returned_code=1)

    def test_other_exception_propagates_without_emitting(self):
        ctx = make_ctx()

        @notify
        def my_command(ctx):
            raise ValueError("boom")

        with patch("safety.decorators.emit_command_executed") as emit:
            with pytest.raises(ValueError, match="boom"):
                my_command(ctx)

        emit.assert_not_called()

    def test_preserves_wrapped_function_metadata(self):
        @notify
        def my_command(ctx):
            """My command docstring."""

        assert my_command.__name__ == "my_command"
        assert my_command.__doc__ == "My command docstring."
