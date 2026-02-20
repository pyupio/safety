"""Shared test helpers for safety.auth tests."""

from unittest.mock import Mock, patch


def patch_configure_auth_session():
    """Patch configure_auth_session to prevent network calls during CLI setup.

    Still sets ``ctx.obj`` so subcommands can access ``ctx.obj.auth.platform``
    etc.  Returns a ``unittest.mock.patch`` context manager / decorator.
    """
    from safety.models import SafetyCLI

    def _noop(ctx, **kwargs):
        if not ctx.obj:
            ctx.obj = SafetyCLI()
        ctx.obj.auth = Mock()

    return patch("safety.cli_util.configure_auth_session", side_effect=_noop)
