"""Unit tests for configure_auth_session() machine token precedence and cleanup."""

from typing import Dict, Optional
from unittest.mock import MagicMock, patch
from concurrent.futures import Future

import click
import pytest

from safety.auth.models import Auth
from safety.config.auth import MachineCredentialConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Common patch targets in safety.auth.cli_utils
_MOD = "safety.auth.cli_utils"


def _make_machine_creds(
    machine_id: str = "test-machine-id",
    machine_token: str = "test-machine-token",
    enrolled_at: str = "2025-01-01T00:00:00Z",
) -> MachineCredentialConfig:
    return MachineCredentialConfig(
        machine_id=machine_id,
        machine_token=machine_token,
        enrolled_at=enrolled_at,
    )


def _build_patches(
    *,
    key: Optional[str] = None,
    machine_creds: Optional[MachineCredentialConfig] = None,
    oauth2_config: Optional[object] = None,
    org: Optional[object] = None,
    host_stage: Optional[object] = None,
    auth_info: Optional[Dict] = None,
):
    """Return a dict of common patches for configure_auth_session tests."""
    mock_platform = MagicMock()
    mock_platform.get_jwks.return_value = {"keys": [{"kid": "1"}]}
    mock_platform._http_client = MagicMock()
    mock_platform.api_key = key
    mock_platform.token = None
    mock_platform.load_auth_token_from_storage = MagicMock()

    patches = {
        f"{_MOD}.get_organization": MagicMock(return_value=org),
        f"{_MOD}.get_host_config": MagicMock(return_value=host_stage),
        f"{_MOD}.get_proxy_config": MagicMock(return_value=None),
        f"{_MOD}.get_tls_config": MagicMock(return_value=MagicMock()),
        f"{_MOD}.MachineCredentialConfig.from_storage": MagicMock(
            return_value=machine_creds
        ),
        f"{_MOD}.AuthConfig.from_storage": MagicMock(return_value=oauth2_config),
        f"{_MOD}._create_platform_client": MagicMock(return_value=mock_platform),
        f"{_MOD}.get_auth_info": MagicMock(return_value=auth_info),
        f"{_MOD}.generate_token": MagicMock(return_value="verifier"),
        f"{_MOD}.get_redirect_url": MagicMock(return_value="http://localhost"),
    }
    return patches, mock_platform


def _run_configure(
    patches: dict,
    *,
    key: Optional[str] = None,
    protected_args: Optional[list] = None,
):
    """Execute configure_auth_session inside a Click context with given patches."""
    from safety.auth.cli_utils import configure_auth_session

    ctx = click.Context(click.Command("test"))
    if protected_args is not None:
        # Click 8.2+ made protected_args a read-only property; fall back to
        # the internal backing attribute when the setter is unavailable.
        try:
            ctx.protected_args = protected_args  # type: ignore[attr-defined]
        except AttributeError:
            ctx._protected_args = protected_args  # type: ignore[attr-defined]
    with ctx:
        stack = {}
        for target, mock_obj in patches.items():
            p = patch(target, mock_obj)
            stack[target] = p.start()

        try:
            configure_auth_session(ctx, key=key)
        finally:
            patch.stopall()

    return ctx


# ---------------------------------------------------------------------------
# Precedence hierarchy
# ---------------------------------------------------------------------------


class TestPrecedenceHierarchy:
    """API key > OAuth2 > machine token > unauthenticated."""

    @pytest.mark.unit
    def test_api_key_takes_precedence_over_machine_token(self) -> None:
        """When API key is provided, machine token path is NOT used."""
        patches, mock_platform = _build_patches(
            key="my-api-key",
            machine_creds=_make_machine_creds(),
        )

        _run_configure(patches, key="my-api-key")

        # JWKS should be fetched (non-machine path)
        mock_platform.get_jwks.assert_called_once()
        # _create_platform_client should receive the API key
        mock_create = patches[f"{_MOD}._create_platform_client"]
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs.get("api_key") == "my-api-key"

    @pytest.mark.unit
    def test_oauth2_takes_precedence_over_machine_token(self) -> None:
        """When OAuth2 tokens exist in storage, machine token path is NOT used."""
        oauth2_cfg = MagicMock()  # truthy → OAuth2 present
        patches, mock_platform = _build_patches(
            machine_creds=_make_machine_creds(),
            oauth2_config=oauth2_cfg,
            auth_info={"email": "user@example.com", "name": "User"},
        )

        _run_configure(patches)

        # JWKS should be fetched (OAuth2 path, not machine)
        mock_platform.get_jwks.assert_called_once()

    @pytest.mark.unit
    def test_machine_token_used_when_no_api_key_no_oauth2(self) -> None:
        """Machine token is selected when API key and OAuth2 are both absent."""
        patches, mock_platform = _build_patches(
            machine_creds=_make_machine_creds(),
            oauth2_config=None,
        )

        _run_configure(patches)

        # JWKS fetch should be SKIPPED
        mock_platform.get_jwks.assert_not_called()

    @pytest.mark.unit
    def test_unauthenticated_when_nothing_available(self) -> None:
        """Falls back to unauthenticated when no key, no OAuth2, no machine creds."""
        patches, mock_platform = _build_patches(
            machine_creds=None,
            oauth2_config=None,
        )

        _run_configure(patches)

        # JWKS should be fetched (standard path)
        mock_platform.get_jwks.assert_called_once()


# ---------------------------------------------------------------------------
# Auth.jwks is None for machine token path
# ---------------------------------------------------------------------------


class TestAuthJwksForMachineToken:
    """Auth.jwks is None for machine token path."""

    @pytest.mark.unit
    def test_auth_jwks_is_none_on_machine_token_path(self) -> None:
        patches, mock_platform = _build_patches(
            machine_creds=_make_machine_creds(),
            oauth2_config=None,
        )

        ctx = _run_configure(patches)
        auth: Auth = ctx.obj.auth
        assert auth.jwks is None

    @pytest.mark.unit
    def test_auth_jwks_is_populated_on_non_machine_path(self) -> None:
        patches, mock_platform = _build_patches(
            machine_creds=None,
            oauth2_config=None,
        )

        ctx = _run_configure(patches)
        auth: Auth = ctx.obj.auth
        # Non-machine path should have fetched JWKS
        assert auth.jwks == {"keys": [{"kid": "1"}]}


# ---------------------------------------------------------------------------
# SafetyContext().account set to "machine:<machine_id>"
# ---------------------------------------------------------------------------


class TestSafetyContextAccount:
    """SafetyContext().account is set correctly for machine token sessions."""

    @pytest.mark.unit
    def test_account_set_to_machine_prefix_on_machine_path(self) -> None:
        patches, _ = _build_patches(
            machine_creds=_make_machine_creds(machine_id="host-abc-123"),
            oauth2_config=None,
        )

        with patch(f"{_MOD}.SafetyContext") as mock_ctx_cls:
            mock_ctx_instance = MagicMock()
            mock_ctx_cls.return_value = mock_ctx_instance

            from safety.auth.cli_utils import configure_auth_session

            ctx = click.Context(click.Command("test"))
            with ctx:
                for target, mock_obj in patches.items():
                    patch(target, mock_obj).start()
                patch(f"{_MOD}.SafetyContext", mock_ctx_cls).start()

                try:
                    configure_auth_session(ctx)
                finally:
                    patch.stopall()

            # SafetyContext().account should be set to "machine:<machine_id>"
            assert mock_ctx_instance.account == "machine:host-abc-123"

    @pytest.mark.unit
    def test_account_set_to_email_on_oauth2_path(self) -> None:
        patches, _ = _build_patches(
            machine_creds=None,
            oauth2_config=None,
            auth_info={"email": "dev@example.com", "name": "Dev"},
        )

        with patch(f"{_MOD}.SafetyContext") as mock_ctx_cls:
            mock_ctx_instance = MagicMock()
            mock_ctx_cls.return_value = mock_ctx_instance

            from safety.auth.cli_utils import configure_auth_session

            ctx = click.Context(click.Command("test"))
            with ctx:
                for target, mock_obj in patches.items():
                    patch(target, mock_obj).start()
                patch(f"{_MOD}.SafetyContext", mock_ctx_cls).start()
                patch(f"{_MOD}.is_email_verified", return_value=True).start()

                try:
                    configure_auth_session(ctx)
                finally:
                    patch.stopall()

            assert mock_ctx_instance.account == "dev@example.com"

    @pytest.mark.unit
    def test_account_empty_when_unauthenticated_no_info(self) -> None:
        patches, _ = _build_patches(
            machine_creds=None,
            oauth2_config=None,
            auth_info=None,
        )

        with patch(f"{_MOD}.SafetyContext") as mock_ctx_cls:
            mock_ctx_instance = MagicMock()
            mock_ctx_cls.return_value = mock_ctx_instance

            from safety.auth.cli_utils import configure_auth_session

            ctx = click.Context(click.Command("test"))
            with ctx:
                for target, mock_obj in patches.items():
                    patch(target, mock_obj).start()
                patch(f"{_MOD}.SafetyContext", mock_ctx_cls).start()

                try:
                    configure_auth_session(ctx)
                finally:
                    patch.stopall()

            assert mock_ctx_instance.account == ""


# ---------------------------------------------------------------------------
# Machine credentials loaded even when not active auth
# ---------------------------------------------------------------------------


class TestMachineCredsAlwaysLoaded:
    """Machine credentials are loaded on every invocation for coexistence."""

    @pytest.mark.unit
    def test_machine_creds_loaded_when_api_key_present(self) -> None:
        """MachineCredentialConfig.from_storage() is called even with API key."""
        patches, _ = _build_patches(
            key="my-api-key",
            machine_creds=_make_machine_creds(),
        )

        mock_from_storage = patches[f"{_MOD}.MachineCredentialConfig.from_storage"]
        _run_configure(patches, key="my-api-key")
        mock_from_storage.assert_called_once()

    @pytest.mark.unit
    def test_machine_creds_loaded_when_oauth2_present(self) -> None:
        """MachineCredentialConfig.from_storage() is called even with OAuth2."""
        patches, _ = _build_patches(
            machine_creds=_make_machine_creds(),
            oauth2_config=MagicMock(),
            auth_info={"email": "user@example.com", "name": "User"},
        )

        mock_from_storage = patches[f"{_MOD}.MachineCredentialConfig.from_storage"]
        _run_configure(patches)
        mock_from_storage.assert_called_once()

    @pytest.mark.unit
    def test_machine_creds_loaded_when_nothing_enrolled(self) -> None:
        """MachineCredentialConfig.from_storage() is called even with no creds."""
        patches, _ = _build_patches(
            machine_creds=None,
            oauth2_config=None,
        )

        mock_from_storage = patches[f"{_MOD}.MachineCredentialConfig.from_storage"]
        _run_configure(patches)
        mock_from_storage.assert_called_once()


# ---------------------------------------------------------------------------
# clean_up_on_close callback
# ---------------------------------------------------------------------------


class TestCleanUpOnClose:
    """Tests for the @ctx.call_on_close cleanup callback registered by
    configure_auth_session.

    The callback must:
    - Close platform._http_client (the single HTTP client)
    - Flush and close event bus if present
    - Handle event bus errors gracefully
    """

    @pytest.mark.unit
    def test_closes_platform_http_client(self) -> None:
        """platform._http_client.close() is called on context close."""
        patches, mock_platform = _build_patches(
            machine_creds=None,
            oauth2_config=None,
        )

        from safety.auth.cli_utils import configure_auth_session

        ctx = click.Context(click.Command("test"))
        with ctx:
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                configure_auth_session(ctx)
            finally:
                patch.stopall()

            mock_client = MagicMock()
            ctx.obj.auth.platform._http_client = mock_client
            ctx.obj.event_bus = None

        mock_client.close.assert_called_once()

    @pytest.mark.unit
    def test_flushes_and_closes_event_bus(self) -> None:
        """Event bus is flushed and stopped when present."""
        patches, mock_platform = _build_patches(
            machine_creds=None,
            oauth2_config=None,
        )

        from safety.auth.cli_utils import configure_auth_session

        ctx = click.Context(click.Command("test"))
        with ctx:
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                configure_auth_session(ctx)
            finally:
                patch.stopall()

            mock_event_bus = MagicMock()
            flush_future = Future()
            flush_future.set_result(None)
            close_future = Future()
            close_future.set_result(None)
            mock_event_bus.emit.side_effect = [flush_future, close_future]
            ctx.obj.event_bus = mock_event_bus

        # event_bus.emit should be called twice (flush + close)
        assert mock_event_bus.emit.call_count == 2
        mock_event_bus.stop.assert_called_once()

    @pytest.mark.unit
    def test_event_bus_error_handled_gracefully(self) -> None:
        """Errors from event bus future.result() are caught and logged,
        not raised."""
        patches, mock_platform = _build_patches(
            machine_creds=None,
            oauth2_config=None,
        )

        from safety.auth.cli_utils import configure_auth_session

        ctx = click.Context(click.Command("test"))
        with ctx:
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                configure_auth_session(ctx)
            finally:
                patch.stopall()

            mock_event_bus = MagicMock()
            # flush future raises
            flush_future = Future()
            flush_future.set_exception(RuntimeError("flush failed"))
            close_future = Future()
            close_future.set_result(None)
            mock_event_bus.emit.side_effect = [flush_future, close_future]
            ctx.obj.event_bus = mock_event_bus

        # Should not raise — error is caught internally
        mock_event_bus.stop.assert_called_once()

    @pytest.mark.unit
    def test_skips_event_bus_when_none(self) -> None:
        """No event bus interaction when ctx.obj.event_bus is falsy."""
        patches, mock_platform = _build_patches(
            machine_creds=None,
            oauth2_config=None,
        )

        from safety.auth.cli_utils import configure_auth_session

        ctx = click.Context(click.Command("test"))
        with ctx:
            for target, mock_obj in patches.items():
                patch(target, mock_obj).start()
            try:
                configure_auth_session(ctx)
            finally:
                patch.stopall()

            ctx.obj.event_bus = None

        # No error — the callback simply skips event bus logic


# ---------------------------------------------------------------------------
# Machine token path passes machine_id / machine_token to platform client
# ---------------------------------------------------------------------------


class TestMachineTokenPathClientCreation:
    """Machine token path passes correct kwargs to _create_platform_client."""

    @pytest.mark.unit
    def test_platform_client_receives_machine_credentials(self) -> None:
        """_create_platform_client is called with machine_id and machine_token."""
        creds = _make_machine_creds(machine_id="device-xyz", machine_token="tok-secret")
        patches, _ = _build_patches(
            machine_creds=creds,
            oauth2_config=None,
        )

        mock_create = patches[f"{_MOD}._create_platform_client"]
        _run_configure(patches)

        # Should be called once (machine token path)
        mock_create.assert_called_once()
        call_kwargs = mock_create.call_args
        assert call_kwargs.kwargs.get("machine_id") == "device-xyz"
        assert call_kwargs.kwargs.get("machine_token") == "tok-secret"

    @pytest.mark.unit
    def test_non_machine_path_does_not_pass_machine_credentials(self) -> None:
        """Standard path does not pass machine_id/machine_token."""
        patches, _ = _build_patches(
            machine_creds=None,
            oauth2_config=None,
        )

        mock_create = patches[f"{_MOD}._create_platform_client"]
        _run_configure(patches)

        call_kwargs = mock_create.call_args
        assert call_kwargs.kwargs.get("machine_id") is None
        assert call_kwargs.kwargs.get("machine_token") is None


# ---------------------------------------------------------------------------
# _is_oauth2_flow_command unit tests
# ---------------------------------------------------------------------------


class TestIsOAuth2FlowCommand:
    """Direct unit tests for _is_oauth2_flow_command helper."""

    @pytest.mark.unit
    @pytest.mark.parametrize(
        "params,expected",
        [
            (["auth", "login"], True),
            (["auth", "register"], True),
            # bare 'safety auth' defaults to login
            (["auth"], True),
            # auth with only flags (no subcommand) defaults to login
            (["auth", "--headless"], True),
            # auth subcommands that are NOT OAuth2 flows
            (["auth", "enroll", "sfek_key"], False),
            (["auth", "status"], False),
            (["auth", "logout"], False),
            # non-auth commands
            (["system-scan", "run"], False),
            (["scan"], False),
            (["check"], False),
            # empty / missing
            ([], False),
            (None, False),
        ],
    )
    def test_detection(self, params, expected) -> None:
        from safety.auth.cli_utils import _is_oauth2_flow_command

        ctx = click.Context(click.Command("test"))
        if params is not None:
            try:
                ctx.protected_args = params  # type: ignore[attr-defined]
            except AttributeError:
                ctx._protected_args = params  # type: ignore[attr-defined]
        assert _is_oauth2_flow_command(ctx) is expected


# ---------------------------------------------------------------------------
# Command-based auth selection (machine token skipped for OAuth2 flows)
# ---------------------------------------------------------------------------


class TestCommandBasedAuthSelection:
    """Machine token auth is skipped for commands that need an OAuth2Client."""

    @pytest.mark.unit
    def test_machine_token_skipped_for_auth_login(self) -> None:
        """On enrolled machine, 'auth login' gets OAuth2 path (not machine token)."""
        patches, mock_platform = _build_patches(
            machine_creds=_make_machine_creds(),
            oauth2_config=None,
        )

        _run_configure(patches, protected_args=["auth", "login"])

        # OAuth2 path: JWKS should be fetched
        mock_platform.get_jwks.assert_called_once()
        # Machine creds should NOT be passed to client
        mock_create = patches[f"{_MOD}._create_platform_client"]
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs.get("machine_id") is None
        assert call_kwargs.get("machine_token") is None

    @pytest.mark.unit
    def test_machine_token_skipped_for_auth_register(self) -> None:
        """On enrolled machine, 'auth register' gets OAuth2 path."""
        patches, mock_platform = _build_patches(
            machine_creds=_make_machine_creds(),
            oauth2_config=None,
        )

        _run_configure(patches, protected_args=["auth", "register"])

        mock_platform.get_jwks.assert_called_once()
        mock_create = patches[f"{_MOD}._create_platform_client"]
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs.get("machine_id") is None

    @pytest.mark.unit
    def test_machine_token_skipped_for_bare_auth(self) -> None:
        """Bare 'safety auth' (defaults to login) gets OAuth2 path."""
        patches, mock_platform = _build_patches(
            machine_creds=_make_machine_creds(),
            oauth2_config=None,
        )

        _run_configure(patches, protected_args=["auth"])

        mock_platform.get_jwks.assert_called_once()
        mock_create = patches[f"{_MOD}._create_platform_client"]
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs.get("machine_id") is None

    @pytest.mark.unit
    def test_machine_token_used_for_auth_enroll(self) -> None:
        """'auth enroll' on enrolled machine uses machine token path."""
        creds = _make_machine_creds(machine_id="dev-xyz", machine_token="tok-secret")
        patches, mock_platform = _build_patches(
            machine_creds=creds,
            oauth2_config=None,
        )

        _run_configure(patches, protected_args=["auth", "enroll", "sfek_key"])

        # Machine token path: JWKS NOT fetched
        mock_platform.get_jwks.assert_not_called()
        # Machine creds passed to client
        mock_create = patches[f"{_MOD}._create_platform_client"]
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs.get("machine_id") == "dev-xyz"
        assert call_kwargs.get("machine_token") == "tok-secret"

    @pytest.mark.unit
    def test_machine_token_used_for_system_scan(self) -> None:
        """'system-scan run' on enrolled machine uses machine token path."""
        creds = _make_machine_creds(machine_id="host-abc", machine_token="tok-scan")
        patches, mock_platform = _build_patches(
            machine_creds=creds,
            oauth2_config=None,
        )

        _run_configure(patches, protected_args=["system-scan", "run"])

        mock_platform.get_jwks.assert_not_called()
        mock_create = patches[f"{_MOD}._create_platform_client"]
        call_kwargs = mock_create.call_args.kwargs
        assert call_kwargs.get("machine_id") == "host-abc"

    @pytest.mark.unit
    def test_machine_token_used_for_auth_status(self) -> None:
        """'auth status' on enrolled machine uses machine token path."""
        creds = _make_machine_creds()
        patches, mock_platform = _build_patches(
            machine_creds=creds,
            oauth2_config=None,
        )

        _run_configure(patches, protected_args=["auth", "status"])

        mock_platform.get_jwks.assert_not_called()

    @pytest.mark.unit
    def test_existing_tests_unaffected_no_protected_args(self) -> None:
        """When protected_args is not set (bare context), machine token still used.

        This ensures the existing test suite behavior is unchanged — bare
        click.Context objects don't have protected_args set.
        """
        patches, mock_platform = _build_patches(
            machine_creds=_make_machine_creds(),
            oauth2_config=None,
        )

        # No protected_args argument → existing behavior
        _run_configure(patches)

        # Machine token path taken (same as before the fix)
        mock_platform.get_jwks.assert_not_called()
