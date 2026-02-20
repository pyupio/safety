from authlib.oauth2.rfc6749 import OAuth2Token
from dataclasses import dataclass
import configparser

from filelock import FileLock
from pathlib import Path
from .main import AUTH_CONFIG_USER
from safety.utils.tokens import get_token_claims
from typing import Any, Dict, Optional, Tuple, cast
import logging

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    access_token: str
    id_token: str
    refresh_token: str

    # Keys used in the auth config file
    _SECTION_AUTH = "auth"
    _KEY_ACCESS_TOKEN = "access_token"
    _KEY_ID_TOKEN = "id_token"
    _KEY_REFRESH_TOKEN = "refresh_token"

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

        return cls(
            access_token=access_token, id_token=id_token, refresh_token=refresh_token
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
            }

            with open(path, "w") as configfile:
                config.write(configfile)

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
        claims = get_token_claims(
            self.access_token, "access_token", jwks, silent_if_expired=True
        )

        if not claims:
            raise ValueError("Invalid access token")

        expires_at = claims.get(self._CLAIMS_EXPIRES_AT, None)

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

        if not machine_id or not machine_token:
            return None

        return cls(
            machine_id=machine_id,
            machine_token=machine_token,
            enrolled_at=enrolled_at,
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
            }

            with open(path, "w") as configfile:
                config.write(configfile)

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
                with open(path, "w") as configfile:
                    config.write(configfile)
