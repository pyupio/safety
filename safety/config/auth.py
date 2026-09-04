# Pre-existing typing/style debt below is out of scope for the JWT migration.
# Modernizing the annotations (PEP 585/604) would break the runtime `cast()`
# calls on Python 3.9, so it is deferred to its own PR.
# ruff: noqa: FA100, I001, UP006, UP035
from authlib.oauth2.rfc6749 import OAuth2Token
from dataclasses import dataclass
import configparser
import os

from filelock import FileLock
from pathlib import Path
from .main import AUTH_CONFIG_USER
from safety.utils.tokens import get_token_claims
from typing import Any, Dict, Optional, Tuple, cast
import logging

logger = logging.getLogger(__name__)


def _write_config_atomically(config: configparser.ConfigParser, path: Path) -> None:
    """Replace the file at `path` with `config` in a single step.

    Writing straight to `path` truncates it before the new contents land.
    This file holds credentials and `from_storage` reads it without taking
    the lock, so that window hands an empty file to any concurrent reader,
    and a write that fails partway through loses the credentials outright.

    Write a sibling temp file and rename over the target instead. `os.replace`
    is atomic on POSIX and Windows, so a reader sees either the old contents
    or the new ones.
    """
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")

    try:
        with open(tmp, "w") as configfile:
            config.write(configfile)
            configfile.flush()
            os.fsync(configfile.fileno())

        if path.exists():
            # `os.replace` keeps the temp file's own mode, so carry the
            # existing one over rather than widening a tightened config.
            os.chmod(tmp, path.stat().st_mode & 0o777)

        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


@dataclass
class AuthConfig:
    access_token: str
    id_token: str
    refresh_token: str
    org_legacy_uuid: str = ""  # from JWT claim, cached for cross-org check

    # Keys used in the auth config file
    _SECTION_AUTH = "auth"
    _KEY_ACCESS_TOKEN = "access_token"
    _KEY_ID_TOKEN = "id_token"
    _KEY_REFRESH_TOKEN = "refresh_token"
    _KEY_ORG_LEGACY_UUID = "org_legacy_uuid"

    # Keys used in the OAuth2Token format
    _KEY_TOKEN_TYPE = "token_type"
    _KEY_EXPIRES_AT = "expires_at"
    _TOKEN_TYPE = "bearer"
    _CLAIMS_EXPIRES_AT = "exp"

    @staticmethod
    def is_valid(
        access_token: Optional[str] = None,
        id_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
    ) -> Optional[Tuple[str, str, str]]:
        """
        A helper to check if the auth config is valid.

        Args:
            access_token (Optional[str]): The access token.
            id_token (Optional[str]): The ID token.
            refresh_token (Optional[str]): The refresh token.

        Returns:
            Optional[Tuple[str, str, str]]: The valid configuration, or None if invalid.
        """

        if not access_token or not id_token or not refresh_token:
            return None

        return access_token, id_token, refresh_token

    @classmethod
    def from_token(cls, token: OAuth2Token) -> Optional["AuthConfig"]:
        access_token = cast(Optional[str], token.get(cls._KEY_ACCESS_TOKEN))
        id_token = cast(Optional[str], token.get(cls._KEY_ID_TOKEN))
        refresh_token = cast(Optional[str], token.get(cls._KEY_REFRESH_TOKEN))

        if not access_token or not id_token or not refresh_token:
            return None

        return cls(
            access_token=access_token,
            id_token=id_token,
            refresh_token=refresh_token,
        )

    @classmethod
    def from_storage(cls, path: Optional[Path] = None) -> Optional["AuthConfig"]:
        if not path:
            path = AUTH_CONFIG_USER

        config = configparser.ConfigParser()
        config.read(path)

        section = (
            config[cls._SECTION_AUTH] if config.has_section(cls._SECTION_AUTH) else {}
        )

        auth_config = cls.is_valid(
            access_token=section.get(cls._KEY_ACCESS_TOKEN),
            id_token=section.get(cls._KEY_ID_TOKEN),
            refresh_token=section.get(cls._KEY_REFRESH_TOKEN),
        )
        if not auth_config:
            return None

        access_token, id_token, refresh_token = auth_config

        org_legacy_uuid = section.get(cls._KEY_ORG_LEGACY_UUID, "")

        return cls(
            access_token=access_token,
            id_token=id_token,
            refresh_token=refresh_token,
            org_legacy_uuid=org_legacy_uuid,
        )

    @classmethod
    def clear(cls, path: Optional[Path] = None):
        # Clears by writing empty values to preserve the [auth] section header.
        # (MachineCredentialConfig.clear() removes the entire section instead.)
        cls(access_token="", id_token="", refresh_token="").save(path)

    def save(self, path: Optional[Path] = None) -> None:
        if not path:
            path = AUTH_CONFIG_USER

        logger.info("Saving auth config to %s", path)

        path.parent.mkdir(parents=True, exist_ok=True)

        lock = FileLock(str(path) + ".lock")

        with lock:
            config = configparser.ConfigParser()
            config.read(path)
            config[self._SECTION_AUTH] = {
                self._KEY_ACCESS_TOKEN: self.access_token,
                self._KEY_ID_TOKEN: self.id_token,
                self._KEY_REFRESH_TOKEN: self.refresh_token,
                self._KEY_ORG_LEGACY_UUID: self.org_legacy_uuid,
            }

            _write_config_atomically(config, path)

    def to_token(self, jwks: Dict[str, Any]) -> OAuth2Token:
        """
        Validate the access token without expiration check.

        Expiration check is not performed to allow authlib to trigger the refresh process.

        Use this method when you want to format the auth config into an OAuth2Token for use with the authlib library.

        Args:
            jwks (Dict[str, Any]): The JSON Web Key Set.

        Returns:
            OAuth2Token: The OAuth2 token.
        """
        decoded = get_token_claims(
            self.access_token, "access_token", jwks, silent_if_expired=True
        )

        if decoded is None:
            raise ValueError("Invalid access token")

        expires_at = decoded.claims.get(self._CLAIMS_EXPIRES_AT, None)

        if not expires_at:
            raise ValueError("Invalid access token, missing expiration time.")

        params = {
            self._KEY_ACCESS_TOKEN: self.access_token,
            self._KEY_REFRESH_TOKEN: self.refresh_token,
            self._KEY_ID_TOKEN: self.id_token,
            self._KEY_TOKEN_TYPE: self._TOKEN_TYPE,
            self._KEY_EXPIRES_AT: expires_at,
        }

        return OAuth2Token.from_dict(params)


@dataclass
class MachineCredentialConfig:
    machine_id: str
    machine_token: str
    enrolled_at: str
    org_id: str = ""  # platform-v2 org UUID (future-proofing)
    org_legacy_uuid: str = ""  # legacy org UUID (used for cross-org comparison)
    org_slug: str = ""  # human-readable org identifier

    _SECTION_MACHINE = "machine"

    @classmethod
    def from_storage(
        cls, path: Optional[Path] = None
    ) -> Optional["MachineCredentialConfig"]:
        if not path:
            path = AUTH_CONFIG_USER

        config = configparser.ConfigParser()
        config.read(path)

        if not config.has_section(cls._SECTION_MACHINE):
            return None

        section = config[cls._SECTION_MACHINE]
        machine_id = section.get("machine_id", "")
        machine_token = section.get("machine_token", "")
        enrolled_at = section.get("enrolled_at", "")
        org_id = section.get("org_id", "")
        org_legacy_uuid = section.get("org_legacy_uuid", "")
        org_slug = section.get("org_slug", "")

        if not machine_id or not machine_token:
            return None

        return cls(
            machine_id=machine_id,
            machine_token=machine_token,
            enrolled_at=enrolled_at,
            org_id=org_id,
            org_legacy_uuid=org_legacy_uuid,
            org_slug=org_slug,
        )

    def save(self, path: Optional[Path] = None) -> None:
        if not path:
            path = AUTH_CONFIG_USER

        path.parent.mkdir(parents=True, exist_ok=True)
        lock = FileLock(str(path) + ".lock")

        with lock:
            config = configparser.ConfigParser()
            config.read(path)
            config[self._SECTION_MACHINE] = {
                "machine_id": self.machine_id,
                "machine_token": self.machine_token,
                "enrolled_at": self.enrolled_at,
                "org_id": self.org_id,
                "org_legacy_uuid": self.org_legacy_uuid,
                "org_slug": self.org_slug,
            }

            _write_config_atomically(config, path)

    @classmethod
    def clear(cls, path: Optional[Path] = None) -> None:
        if not path:
            path = AUTH_CONFIG_USER

        lock = FileLock(str(path) + ".lock")

        with lock:
            config = configparser.ConfigParser()
            config.read(path)
            if config.has_section(cls._SECTION_MACHINE):
                config.remove_section(cls._SECTION_MACHINE)
                _write_config_atomically(config, path)
