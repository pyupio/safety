import configparser
import multiprocessing
import time
from pathlib import Path
from typing import Dict, Optional
from unittest.mock import patch

import pytest
from authlib.oauth2.rfc6749 import OAuth2Token

from safety.config.auth import AuthConfig, MachineCredentialConfig


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def config_file_factory(tmp_path: Path):
    """
    Factory fixture to create auth.ini files with custom sections.
    """

    def _create_config(
        auth_section: Optional[Dict[str, str]] = None,
        machine_section: Optional[Dict[str, str]] = None,
    ) -> Path:
        config = configparser.ConfigParser()
        if auth_section is not None:
            config["auth"] = auth_section
        if machine_section is not None:
            config["machine"] = machine_section

        config_path = tmp_path / "auth.ini"
        with open(config_path, "w") as f:
            config.write(f)
        return config_path

    return _create_config


# ─────────────────────────────────────────────────────────────────────────────
# MachineCredentialConfig.from_storage Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestMachineCredentialConfigFromStorage:
    """Tests for MachineCredentialConfig.from_storage()."""

    @pytest.mark.unit
    def test_returns_none_when_no_machine_section(self, config_file_factory) -> None:
        config_path = config_file_factory(auth_section={"access_token": "tok"})
        result = MachineCredentialConfig.from_storage(path=config_path)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_file_does_not_exist(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "nonexistent.ini"
        result = MachineCredentialConfig.from_storage(path=nonexistent)
        assert result is None

    @pytest.mark.unit
    def test_returns_populated_config_when_machine_section_exists(
        self, config_file_factory
    ) -> None:
        config_path = config_file_factory(
            machine_section={
                "machine_id": "m-abc123",
                "machine_token": "tok-secret",
                "enrolled_at": "2025-01-15T10:30:00Z",
            }
        )
        result = MachineCredentialConfig.from_storage(path=config_path)

        assert result is not None
        assert result.machine_id == "m-abc123"
        assert result.machine_token == "tok-secret"
        assert result.enrolled_at == "2025-01-15T10:30:00Z"

    @pytest.mark.unit
    def test_returns_none_when_machine_id_missing(self, config_file_factory) -> None:
        config_path = config_file_factory(
            machine_section={
                "machine_token": "tok-secret",
                "enrolled_at": "2025-01-15T10:30:00Z",
            }
        )
        result = MachineCredentialConfig.from_storage(path=config_path)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_machine_token_missing(self, config_file_factory) -> None:
        config_path = config_file_factory(
            machine_section={
                "machine_id": "m-abc123",
                "enrolled_at": "2025-01-15T10:30:00Z",
            }
        )
        result = MachineCredentialConfig.from_storage(path=config_path)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_both_required_fields_empty(
        self, config_file_factory
    ) -> None:
        """Explicit check: empty strings for machine_id and machine_token → None."""
        config_path = config_file_factory(
            machine_section={
                "machine_id": "",
                "machine_token": "",
                "enrolled_at": "2025-01-15T10:30:00Z",
            }
        )
        result = MachineCredentialConfig.from_storage(path=config_path)
        assert result is None

    @pytest.mark.unit
    def test_returns_config_with_empty_enrolled_at(self, config_file_factory) -> None:
        """enrolled_at is optional — empty string is acceptable."""
        config_path = config_file_factory(
            machine_section={
                "machine_id": "m-abc123",
                "machine_token": "tok-secret",
            }
        )
        result = MachineCredentialConfig.from_storage(path=config_path)

        assert result is not None
        assert result.machine_id == "m-abc123"
        assert result.machine_token == "tok-secret"
        assert result.enrolled_at == ""


# ─────────────────────────────────────────────────────────────────────────────
# MachineCredentialConfig.save Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestMachineCredentialConfigSave:
    """Tests for MachineCredentialConfig.save()."""

    @pytest.mark.unit
    def test_save_persists_all_fields(self, tmp_path: Path) -> None:
        config_path = tmp_path / "auth.ini"
        cred = MachineCredentialConfig(
            machine_id="m-abc123",
            machine_token="tok-secret",
            enrolled_at="2025-01-15T10:30:00Z",
        )

        cred.save(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert config.has_section("machine")
        assert config["machine"]["machine_id"] == "m-abc123"
        assert config["machine"]["machine_token"] == "tok-secret"
        assert config["machine"]["enrolled_at"] == "2025-01-15T10:30:00Z"

    @pytest.mark.unit
    def test_save_preserves_existing_auth_section(self, config_file_factory) -> None:
        config_path = config_file_factory(
            auth_section={
                "access_token": "at-existing",
                "id_token": "id-existing",
                "refresh_token": "rt-existing",
            }
        )
        cred = MachineCredentialConfig(
            machine_id="m-abc123",
            machine_token="tok-secret",
            enrolled_at="2025-01-15T10:30:00Z",
        )

        cred.save(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        # Machine section written
        assert config["machine"]["machine_id"] == "m-abc123"
        # Auth section preserved
        assert config.has_section("auth")
        assert config["auth"]["access_token"] == "at-existing"
        assert config["auth"]["id_token"] == "id-existing"
        assert config["auth"]["refresh_token"] == "rt-existing"

    @pytest.mark.unit
    def test_save_creates_parent_directory(self, tmp_path: Path) -> None:
        nested_path = tmp_path / "deep" / "nested" / "auth.ini"
        cred = MachineCredentialConfig(
            machine_id="m-abc123",
            machine_token="tok-secret",
            enrolled_at="2025-01-15T10:30:00Z",
        )

        cred.save(path=nested_path)

        assert nested_path.exists()
        config = configparser.ConfigParser()
        config.read(nested_path)
        assert config["machine"]["machine_id"] == "m-abc123"

    @pytest.mark.unit
    def test_save_overwrites_existing_machine_section(
        self, config_file_factory
    ) -> None:
        """Saving new credentials replaces old ones entirely."""
        config_path = config_file_factory(
            machine_section={
                "machine_id": "m-old",
                "machine_token": "tok-old",
                "enrolled_at": "2024-01-01T00:00:00Z",
            }
        )
        new_cred = MachineCredentialConfig(
            machine_id="m-new",
            machine_token="tok-new",
            enrolled_at="2025-06-01T00:00:00Z",
        )

        new_cred.save(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert config["machine"]["machine_id"] == "m-new"
        assert config["machine"]["machine_token"] == "tok-new"
        assert config["machine"]["enrolled_at"] == "2025-06-01T00:00:00Z"

    @pytest.mark.unit
    def test_save_roundtrips_with_from_storage(self, tmp_path: Path) -> None:
        config_path = tmp_path / "auth.ini"
        original = MachineCredentialConfig(
            machine_id="m-roundtrip",
            machine_token="tok-roundtrip",
            enrolled_at="2025-06-01T00:00:00Z",
        )

        original.save(path=config_path)
        loaded = MachineCredentialConfig.from_storage(path=config_path)

        assert loaded is not None
        assert loaded.machine_id == original.machine_id
        assert loaded.machine_token == original.machine_token
        assert loaded.enrolled_at == original.enrolled_at
        assert loaded.org_slug == original.org_slug


# ─────────────────────────────────────────────────────────────────────────────
# MachineCredentialConfig.clear Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestMachineCredentialConfigClear:
    """Tests for MachineCredentialConfig.clear()."""

    @pytest.mark.unit
    def test_clear_removes_machine_section(self, config_file_factory) -> None:
        config_path = config_file_factory(
            machine_section={
                "machine_id": "m-abc123",
                "machine_token": "tok-secret",
                "enrolled_at": "2025-01-15T10:30:00Z",
            }
        )

        MachineCredentialConfig.clear(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert not config.has_section("machine")

    @pytest.mark.unit
    def test_clear_preserves_auth_section(self, config_file_factory) -> None:
        config_path = config_file_factory(
            auth_section={
                "access_token": "at-keep",
                "id_token": "id-keep",
                "refresh_token": "rt-keep",
            },
            machine_section={
                "machine_id": "m-abc123",
                "machine_token": "tok-secret",
                "enrolled_at": "2025-01-15T10:30:00Z",
            },
        )

        MachineCredentialConfig.clear(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert not config.has_section("machine")
        assert config.has_section("auth")
        assert config["auth"]["access_token"] == "at-keep"
        assert config["auth"]["id_token"] == "id-keep"
        assert config["auth"]["refresh_token"] == "rt-keep"

    @pytest.mark.unit
    def test_clear_noop_when_no_machine_section(self, config_file_factory) -> None:
        config_path = config_file_factory(auth_section={"access_token": "at-only"})

        MachineCredentialConfig.clear(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert not config.has_section("machine")
        assert config["auth"]["access_token"] == "at-only"

    @pytest.mark.unit
    def test_clear_noop_when_file_does_not_exist(self, tmp_path: Path) -> None:
        """Clearing a nonexistent file should not raise or create the file."""
        nonexistent = tmp_path / "nonexistent.ini"

        MachineCredentialConfig.clear(path=nonexistent)

        assert not nonexistent.exists()

    @pytest.mark.unit
    def test_clear_removes_only_section_leaving_empty_file(
        self, config_file_factory
    ) -> None:
        """When machine is the only section, clear leaves a valid but empty config."""
        config_path = config_file_factory(
            machine_section={
                "machine_id": "m-only",
                "machine_token": "tok-only",
                "enrolled_at": "2025-01-15T10:30:00Z",
            }
        )

        MachineCredentialConfig.clear(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert not config.has_section("machine")
        assert len(config.sections()) == 0


# ─────────────────────────────────────────────────────────────────────────────
# AuthConfig.save Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthConfigSave:
    """Tests for AuthConfig.save()."""

    @pytest.mark.unit
    def test_save_persists_under_auth_section(self, tmp_path: Path) -> None:
        config_path = tmp_path / "auth.ini"
        auth = AuthConfig(
            access_token="at-persist",
            id_token="id-persist",
            refresh_token="rt-persist",
        )

        auth.save(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert config.has_section("auth")
        assert config["auth"]["access_token"] == "at-persist"
        assert config["auth"]["id_token"] == "id-persist"
        assert config["auth"]["refresh_token"] == "rt-persist"

    @pytest.mark.unit
    def test_save_preserves_existing_machine_section(self, config_file_factory) -> None:
        config_path = config_file_factory(
            machine_section={
                "machine_id": "m-keep",
                "machine_token": "tok-keep",
                "enrolled_at": "2025-01-15T10:30:00Z",
            }
        )
        auth = AuthConfig(
            access_token="at-new",
            id_token="id-new",
            refresh_token="rt-new",
        )

        auth.save(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert config["auth"]["access_token"] == "at-new"
        assert config["machine"]["machine_id"] == "m-keep"
        assert config["machine"]["machine_token"] == "tok-keep"


# ─────────────────────────────────────────────────────────────────────────────
# AuthConfig.is_valid Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthConfigIsValid:
    """Tests for AuthConfig.is_valid()."""

    @pytest.mark.unit
    def test_returns_tuple_when_all_fields_present(self) -> None:
        result = AuthConfig.is_valid(
            access_token="at", id_token="id", refresh_token="rt"
        )
        assert result == ("at", "id", "rt")

    @pytest.mark.unit
    def test_returns_none_when_access_token_missing(self) -> None:
        result = AuthConfig.is_valid(
            access_token=None, id_token="id", refresh_token="rt"
        )
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_id_token_missing(self) -> None:
        result = AuthConfig.is_valid(
            access_token="at", id_token=None, refresh_token="rt"
        )
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_refresh_token_missing(self) -> None:
        result = AuthConfig.is_valid(
            access_token="at", id_token="id", refresh_token=None
        )
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_all_fields_none(self) -> None:
        result = AuthConfig.is_valid(
            access_token=None, id_token=None, refresh_token=None
        )
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_access_token_empty_string(self) -> None:
        result = AuthConfig.is_valid(access_token="", id_token="id", refresh_token="rt")
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_no_args(self) -> None:
        result = AuthConfig.is_valid()
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# AuthConfig.from_storage Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthConfigFromStorage:
    """Tests for AuthConfig.from_storage()."""

    @pytest.mark.unit
    def test_returns_none_when_no_auth_section(self, config_file_factory) -> None:
        config_path = config_file_factory(
            machine_section={"machine_id": "m-1", "machine_token": "tok"}
        )
        result = AuthConfig.from_storage(path=config_path)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_file_does_not_exist(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "nonexistent.ini"
        result = AuthConfig.from_storage(path=nonexistent)
        assert result is None

    @pytest.mark.unit
    def test_returns_populated_config_when_auth_section_exists(
        self, config_file_factory
    ) -> None:
        config_path = config_file_factory(
            auth_section={
                "access_token": "at-abc123",
                "id_token": "id-abc123",
                "refresh_token": "rt-abc123",
            }
        )
        result = AuthConfig.from_storage(path=config_path)

        assert result is not None
        assert result.access_token == "at-abc123"
        assert result.id_token == "id-abc123"
        assert result.refresh_token == "rt-abc123"

    @pytest.mark.unit
    def test_returns_none_when_access_token_missing(self, config_file_factory) -> None:
        config_path = config_file_factory(
            auth_section={
                "id_token": "id-abc123",
                "refresh_token": "rt-abc123",
            }
        )
        result = AuthConfig.from_storage(path=config_path)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_id_token_missing(self, config_file_factory) -> None:
        config_path = config_file_factory(
            auth_section={
                "access_token": "at-abc123",
                "refresh_token": "rt-abc123",
            }
        )
        result = AuthConfig.from_storage(path=config_path)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_refresh_token_missing(self, config_file_factory) -> None:
        config_path = config_file_factory(
            auth_section={
                "access_token": "at-abc123",
                "id_token": "id-abc123",
            }
        )
        result = AuthConfig.from_storage(path=config_path)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_all_fields_empty(self, config_file_factory) -> None:
        config_path = config_file_factory(
            auth_section={
                "access_token": "",
                "id_token": "",
                "refresh_token": "",
            }
        )
        result = AuthConfig.from_storage(path=config_path)
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# AuthConfig.from_token Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthConfigFromToken:
    """Tests for AuthConfig.from_token()."""

    @pytest.mark.unit
    def test_returns_config_from_valid_token(self) -> None:
        token = OAuth2Token(
            {
                "access_token": "at-from-token",
                "id_token": "id-from-token",
                "refresh_token": "rt-from-token",
                "token_type": "bearer",
            }
        )
        result = AuthConfig.from_token(token)

        assert result is not None
        assert result.access_token == "at-from-token"
        assert result.id_token == "id-from-token"
        assert result.refresh_token == "rt-from-token"

    @pytest.mark.unit
    def test_returns_none_when_access_token_missing(self) -> None:
        token = OAuth2Token(
            {
                "id_token": "id-from-token",
                "refresh_token": "rt-from-token",
                "token_type": "bearer",
            }
        )
        result = AuthConfig.from_token(token)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_id_token_missing(self) -> None:
        token = OAuth2Token(
            {
                "access_token": "at-from-token",
                "refresh_token": "rt-from-token",
                "token_type": "bearer",
            }
        )
        result = AuthConfig.from_token(token)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_refresh_token_missing(self) -> None:
        token = OAuth2Token(
            {
                "access_token": "at-from-token",
                "id_token": "id-from-token",
                "token_type": "bearer",
            }
        )
        result = AuthConfig.from_token(token)
        assert result is None

    @pytest.mark.unit
    def test_returns_none_when_token_empty(self) -> None:
        token = OAuth2Token({})
        result = AuthConfig.from_token(token)
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# AuthConfig.to_token Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthConfigToToken:
    """Tests for AuthConfig.to_token()."""

    @pytest.mark.unit
    def test_returns_oauth2_token_with_all_fields(self) -> None:
        auth = AuthConfig(
            access_token="at-test",
            id_token="id-test",
            refresh_token="rt-test",
        )
        mock_claims = {"exp": 1700000000}

        with patch("safety.config.auth.get_token_claims", return_value=mock_claims):
            token = auth.to_token(jwks={"keys": []})

        assert token["access_token"] == "at-test"
        assert token["id_token"] == "id-test"
        assert token["refresh_token"] == "rt-test"
        assert token["token_type"] == "bearer"
        assert token["expires_at"] == 1700000000

    @pytest.mark.unit
    def test_raises_when_claims_are_none(self) -> None:
        auth = AuthConfig(
            access_token="at-bad",
            id_token="id-bad",
            refresh_token="rt-bad",
        )

        with patch("safety.config.auth.get_token_claims", return_value=None):
            with pytest.raises(ValueError, match="Invalid access token"):
                auth.to_token(jwks={"keys": []})

    @pytest.mark.unit
    def test_raises_when_expiration_missing(self) -> None:
        auth = AuthConfig(
            access_token="at-noexp",
            id_token="id-noexp",
            refresh_token="rt-noexp",
        )
        mock_claims = {"sub": "user-123"}  # Has content but no "exp" key

        with patch("safety.config.auth.get_token_claims", return_value=mock_claims):
            with pytest.raises(ValueError, match="missing expiration"):
                auth.to_token(jwks={"keys": []})

    @pytest.mark.unit
    def test_passes_correct_args_to_get_token_claims(self) -> None:
        auth = AuthConfig(
            access_token="at-verify",
            id_token="id-verify",
            refresh_token="rt-verify",
        )
        jwks = {"keys": [{"kid": "test-key"}]}
        mock_claims = {"exp": 1700000000}

        with patch(
            "safety.config.auth.get_token_claims", return_value=mock_claims
        ) as mock_get_claims:
            auth.to_token(jwks=jwks)

            mock_get_claims.assert_called_once_with(
                "at-verify", "access_token", jwks, silent_if_expired=True
            )


# ─────────────────────────────────────────────────────────────────────────────
# AuthConfig.clear Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAuthConfigClear:
    """Tests for AuthConfig.clear()."""

    @pytest.mark.unit
    def test_clear_writes_empty_strings(self, config_file_factory) -> None:
        config_path = config_file_factory(
            auth_section={
                "access_token": "at-existing",
                "id_token": "id-existing",
                "refresh_token": "rt-existing",
            }
        )

        AuthConfig.clear(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert config.has_section("auth")
        assert config["auth"]["access_token"] == ""
        assert config["auth"]["id_token"] == ""
        assert config["auth"]["refresh_token"] == ""

    @pytest.mark.unit
    def test_clear_preserves_machine_section(self, config_file_factory) -> None:
        config_path = config_file_factory(
            auth_section={
                "access_token": "at-clear",
                "id_token": "id-clear",
                "refresh_token": "rt-clear",
            },
            machine_section={
                "machine_id": "m-keep",
                "machine_token": "tok-keep",
                "enrolled_at": "2025-01-15T10:30:00Z",
            },
        )

        AuthConfig.clear(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        # Auth section still present but with empty values
        assert config.has_section("auth")
        assert config["auth"]["access_token"] == ""
        # Machine section preserved
        assert config.has_section("machine")
        assert config["machine"]["machine_id"] == "m-keep"
        assert config["machine"]["machine_token"] == "tok-keep"
        assert config["machine"]["enrolled_at"] == "2025-01-15T10:30:00Z"

    @pytest.mark.unit
    def test_clear_creates_auth_section_if_missing(self, tmp_path: Path) -> None:
        """Clearing when no auth section exists creates one with empty values."""
        config_path = tmp_path / "auth.ini"

        AuthConfig.clear(path=config_path)

        config = configparser.ConfigParser()
        config.read(config_path)
        assert config.has_section("auth")
        assert config["auth"]["access_token"] == ""

    @pytest.mark.unit
    def test_clear_roundtrip_invalidates_from_storage(
        self, config_file_factory
    ) -> None:
        """After clear(), from_storage() should return None."""
        config_path = config_file_factory(
            auth_section={
                "access_token": "at-valid",
                "id_token": "id-valid",
                "refresh_token": "rt-valid",
            }
        )
        # Valid before clear
        assert AuthConfig.from_storage(path=config_path) is not None

        AuthConfig.clear(path=config_path)

        # Invalid after clear
        assert AuthConfig.from_storage(path=config_path) is None


# ─────────────────────────────────────────────────────────────────────────────
# Concurrent Access Tests
# ─────────────────────────────────────────────────────────────────────────────


def _concurrent_writer_machine(config_path_str: str, worker_id: int, iterations: int):
    """
    Worker function for concurrent write tests.
    Writes machine credentials multiple times with worker-specific values.

    Args:
        config_path_str: String path (not Path object) for Windows spawn compatibility
        worker_id: Unique worker identifier
        iterations: Number of write operations to perform
    """
    config_path = Path(config_path_str)
    for i in range(iterations):
        cred = MachineCredentialConfig(
            machine_id=f"m-worker{worker_id}-iter{i}",
            machine_token=f"tok-worker{worker_id}-iter{i}",
            enrolled_at=f"2025-01-{worker_id:02d}T{i:02d}:00:00Z",
        )
        cred.save(path=config_path)
        time.sleep(0.001)  # Small delay to increase interleaving


def _concurrent_writer_auth(config_path_str: str, worker_id: int, iterations: int):
    """
    Worker function for concurrent write tests for AuthConfig.
    Writes auth tokens multiple times with worker-specific values.

    Args:
        config_path_str: String path (not Path object) for Windows spawn compatibility
        worker_id: Unique worker identifier
        iterations: Number of write operations to perform
    """
    config_path = Path(config_path_str)
    for i in range(iterations):
        auth = AuthConfig(
            access_token=f"at-worker{worker_id}-iter{i}",
            id_token=f"id-worker{worker_id}-iter{i}",
            refresh_token=f"rt-worker{worker_id}-iter{i}",
        )
        auth.save(path=config_path)
        time.sleep(0.001)  # Small delay to increase interleaving


def _concurrent_clearer_machine(config_path_str: str, iterations: int):
    """
    Worker function that clears machine credentials repeatedly.

    Args:
        config_path_str: String path (not Path object) for Windows spawn compatibility
        iterations: Number of clear operations to perform
    """
    config_path = Path(config_path_str)
    for _ in range(iterations):
        MachineCredentialConfig.clear(path=config_path)
        time.sleep(0.001)


def _concurrent_clearer_auth(config_path_str: str, iterations: int):
    """
    Worker function that clears auth config repeatedly.

    Args:
        config_path_str: String path (not Path object) for Windows spawn compatibility
        iterations: Number of clear operations to perform
    """
    config_path = Path(config_path_str)
    for _ in range(iterations):
        AuthConfig.clear(path=config_path)
        time.sleep(0.001)


class TestConcurrentAccess:
    """
    Integration tests for concurrent file access via FileLock.

    These tests verify that:
    1. Concurrent writes don't corrupt the config file
    2. FileLock properly serializes access across processes
    3. Files remain valid INI format after concurrent operations
    """

    @pytest.mark.integration
    def test_concurrent_machine_credential_writes_dont_corrupt_file(
        self, tmp_path: Path
    ) -> None:
        """Multiple processes writing machine credentials should not corrupt the file."""
        config_path = tmp_path / "auth.ini"
        num_workers = 3
        iterations = 5

        processes = []
        for worker_id in range(num_workers):
            p = multiprocessing.Process(
                target=_concurrent_writer_machine,
                args=(str(config_path), worker_id, iterations),
            )
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=30)
            if p.exitcode is None:
                # Process still running - likely deadlock or stuck
                p.terminate()
                p.join(timeout=5)
                pytest.fail(
                    "Worker process timed out after 30s. "
                    "This may indicate a FileLock deadlock."
                )
            assert p.exitcode == 0, f"Worker process failed with exit code {p.exitcode}"

        # File should still be valid INI format
        config = configparser.ConfigParser()
        config.read(config_path)
        assert config.has_section("machine")

        # Should be able to load a valid credential (from the last writer)
        result = MachineCredentialConfig.from_storage(path=config_path)
        assert result is not None
        assert result.machine_id.startswith("m-worker")
        assert result.machine_token.startswith("tok-worker")

    @pytest.mark.integration
    def test_concurrent_auth_config_writes_dont_corrupt_file(
        self, tmp_path: Path
    ) -> None:
        """Multiple processes writing auth config should not corrupt the file."""
        config_path = tmp_path / "auth.ini"
        num_workers = 3
        iterations = 5

        processes = []
        for worker_id in range(num_workers):
            p = multiprocessing.Process(
                target=_concurrent_writer_auth,
                args=(str(config_path), worker_id, iterations),
            )
            processes.append(p)
            p.start()

        for p in processes:
            p.join(timeout=30)
            if p.exitcode is None:
                # Process still running - likely deadlock or stuck
                p.terminate()
                p.join(timeout=5)
                pytest.fail(
                    "Worker process timed out after 30s. "
                    "This may indicate a FileLock deadlock."
                )
            assert p.exitcode == 0, f"Worker process failed with exit code {p.exitcode}"

        # File should still be valid INI format
        config = configparser.ConfigParser()
        config.read(config_path)
        assert config.has_section("auth")

        # Should be able to load a valid config (from the last writer)
        result = AuthConfig.from_storage(path=config_path)
        assert result is not None
        assert result.access_token.startswith("at-worker")

    @pytest.mark.integration
    def test_concurrent_machine_save_and_clear_dont_corrupt_file(
        self, tmp_path: Path
    ) -> None:
        """Concurrent saves and clears should not corrupt the file."""
        config_path = tmp_path / "auth.ini"
        iterations = 10

        # Create initial config
        initial = MachineCredentialConfig(
            machine_id="m-initial",
            machine_token="tok-initial",
            enrolled_at="2025-01-01T00:00:00Z",
        )
        initial.save(path=config_path)

        # Start one writer and one clearer
        writer = multiprocessing.Process(
            target=_concurrent_writer_machine, args=(config_path, 1, iterations)
        )
        clearer = multiprocessing.Process(
            target=_concurrent_clearer_machine, args=(str(config_path), iterations)
        )

        writer.start()
        clearer.start()

        writer.join(timeout=10)
        clearer.join(timeout=10)

        assert writer.exitcode == 0, "Writer process failed"
        assert clearer.exitcode == 0, "Clearer process failed"

        # File should still be valid INI format
        config = configparser.ConfigParser()
        config.read(config_path)

        # Verify file is in a valid end state (either writer or clearer won)
        if config.has_section("machine"):
            # Writer won - verify it's a valid config
            result = MachineCredentialConfig.from_storage(path=config_path)
            assert result is not None, "If machine section exists, it must be valid"
            assert result.machine_id.startswith("m-worker"), (
                f"Invalid machine_id: {result.machine_id}"
            )
            assert result.machine_token.startswith("tok-worker"), (
                f"Invalid machine_token: {result.machine_token}"
            )
        else:
            # Clearer won - verify section is truly gone
            assert not config.has_section("machine")
            assert MachineCredentialConfig.from_storage(path=config_path) is None

    @pytest.mark.integration
    def test_concurrent_auth_save_and_clear_dont_corrupt_file(
        self, tmp_path: Path
    ) -> None:
        """Concurrent auth saves and clears should not corrupt the file."""
        config_path = tmp_path / "auth.ini"
        iterations = 10

        # Create initial config
        initial = AuthConfig(
            access_token="at-initial",
            id_token="id-initial",
            refresh_token="rt-initial",
        )
        initial.save(path=config_path)

        # Start one writer and one clearer
        writer = multiprocessing.Process(
            target=_concurrent_writer_auth, args=(config_path, 1, iterations)
        )
        clearer = multiprocessing.Process(
            target=_concurrent_clearer_auth, args=(str(config_path), iterations)
        )

        writer.start()
        clearer.start()

        writer.join(timeout=10)
        clearer.join(timeout=10)

        assert writer.exitcode == 0, "Writer process failed"
        assert clearer.exitcode == 0, "Clearer process failed"

        # File should still be valid INI format
        config = configparser.ConfigParser()
        config.read(config_path)

        # Verify file is in a valid end state (either writer or clearer won)
        if config.has_section("auth"):
            # Check if auth section has valid data (writer won) or empty strings (clearer won)
            result = AuthConfig.from_storage(path=config_path)
            if result is not None:
                # Writer won - verify it's valid
                assert result.access_token.startswith("at-worker"), (
                    f"Invalid access_token: {result.access_token}"
                )
            # else: Clearer won but section still exists with empty values (valid state)
        # If no auth section at all, that's also a valid end state

    @pytest.mark.integration
    def test_mixed_machine_and_auth_concurrent_writes(self, tmp_path: Path) -> None:
        """Concurrent writes to different sections should preserve both."""
        config_path = tmp_path / "auth.ini"
        iterations = 5

        # Start writers for both machine and auth sections
        machine_writer = multiprocessing.Process(
            target=_concurrent_writer_machine, args=(config_path, 1, iterations)
        )
        auth_writer = multiprocessing.Process(
            target=_concurrent_writer_auth, args=(config_path, 1, iterations)
        )

        machine_writer.start()
        auth_writer.start()

        machine_writer.join(timeout=10)
        auth_writer.join(timeout=10)

        assert machine_writer.exitcode == 0, "Machine writer failed"
        assert auth_writer.exitcode == 0, "Auth writer failed"

        # Both sections should exist and be valid
        config = configparser.ConfigParser()
        config.read(config_path)
        assert config.has_section("machine")
        assert config.has_section("auth")

        # Should be able to load both configs
        machine_config = MachineCredentialConfig.from_storage(path=config_path)
        auth_config = AuthConfig.from_storage(path=config_path)

        assert machine_config is not None
        assert auth_config is not None


def _concurrent_reader_machine(
    config_path_str: str, iterations: int, results: multiprocessing.Queue
):
    """
    Worker function that repeatedly reads config.
    Verifies that reads never return corrupted data.

    Args:
        config_path_str: String path (not Path object) for Windows spawn compatibility
        iterations: Number of read operations to perform
        results: Queue to report read results
    """
    config_path = Path(config_path_str)
    for _ in range(iterations):
        result = MachineCredentialConfig.from_storage(path=config_path)
        # result should be either valid config or None, never corrupted
        if result is not None:
            # Validate the structure - if machine section exists, it must be complete
            assert result.machine_id.startswith("m-"), (
                f"Invalid machine_id: {result.machine_id}"
            )
            assert result.machine_token.startswith("tok-"), (
                f"Invalid machine_token: {result.machine_token}"
            )
        results.put(("success", result is not None))
        time.sleep(0.001)


class TestConcurrentReadAccess:
    """
    Tests for concurrent read access to config files.

    Verifies that from_storage() can safely read while other processes
    are writing, without seeing corrupted/partial data.
    """

    @pytest.mark.integration
    def test_concurrent_read_and_write_dont_corrupt(self, tmp_path: Path) -> None:
        """Readers should never see corrupted data, even during writes."""
        config_path = tmp_path / "auth.ini"

        # Create initial config
        initial = MachineCredentialConfig(
            machine_id="m-initial",
            machine_token="tok-initial",
            enrolled_at="2025-01-01T00:00:00Z",
        )
        initial.save(path=config_path)

        results = multiprocessing.Queue()
        iterations_write = 20
        iterations_read = 20

        # Start 1 writer and 2 readers
        writer = multiprocessing.Process(
            target=_concurrent_writer_machine, args=(config_path, 1, iterations_write)
        )
        reader1 = multiprocessing.Process(
            target=_concurrent_reader_machine,
            args=(str(config_path), iterations_read, results),
        )
        reader2 = multiprocessing.Process(
            target=_concurrent_reader_machine,
            args=(str(config_path), iterations_read, results),
        )

        writer.start()
        reader1.start()
        reader2.start()

        writer.join(timeout=10)
        reader1.join(timeout=10)
        reader2.join(timeout=10)

        assert writer.exitcode == 0, "Writer process failed"
        assert reader1.exitcode == 0, "Reader1 process failed"
        assert reader2.exitcode == 0, "Reader2 process failed"

        # Verify all reads returned valid data (never corrupted)
        success_count = 0
        none_count = 0
        while not results.empty():
            status, has_data = results.get()
            assert status == "success", "Reader should never fail with corrupted data"
            if has_data:
                success_count += 1
            else:
                none_count += 1

        # We should have some successful reads (at least from initial state)
        assert success_count > 0, "Should have read valid config at least once"
        # Total should match iterations from both readers
        assert success_count + none_count == iterations_read * 2

    @pytest.mark.integration
    def test_concurrent_reads_while_clearing(self, tmp_path: Path) -> None:
        """Verify reads don't fail when clear() is called concurrently."""
        config_path = tmp_path / "auth.ini"

        # Create initial config
        initial = MachineCredentialConfig(
            machine_id="m-initial",
            machine_token="tok-initial",
            enrolled_at="2025-01-01T00:00:00Z",
        )
        initial.save(path=config_path)

        results = multiprocessing.Queue()
        iterations = 15

        # Start 1 clearer and 2 readers
        clearer = multiprocessing.Process(
            target=_concurrent_clearer_machine, args=(str(config_path), iterations)
        )
        reader1 = multiprocessing.Process(
            target=_concurrent_reader_machine,
            args=(str(config_path), iterations, results),
        )
        reader2 = multiprocessing.Process(
            target=_concurrent_reader_machine,
            args=(str(config_path), iterations, results),
        )

        clearer.start()
        reader1.start()
        reader2.start()

        clearer.join(timeout=10)
        reader1.join(timeout=10)
        reader2.join(timeout=10)

        assert clearer.exitcode == 0, "Clearer process failed"
        assert reader1.exitcode == 0, "Reader1 process failed"
        assert reader2.exitcode == 0, "Reader2 process failed"

        # Verify all reads succeeded (returned either valid config or None)
        success_count = 0
        while not results.empty():
            status, _ = results.get()
            assert status == "success"
            success_count += 1

        assert success_count == iterations * 2
