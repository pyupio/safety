from dataclasses import dataclass
import os
from typing import TYPE_CHECKING, Any, List, Optional, Dict, Union

from authlib.integrations.base_client import BaseOAuth

from safety_schemas.models import Stage

if TYPE_CHECKING:
    from authlib.integrations.httpx_client import OAuth2Client
    from safety.platform import SafetyPlatformClient
    import httpx


@dataclass
class Organization:
    id: str
    name: str

    def to_dict(self) -> Dict:
        """
        Convert the Organization instance to a dictionary.

        Returns:
            dict: The dictionary representation of the organization.
        """
        return {"id": self.id, "name": self.name}


@dataclass
class Auth:
    org: Optional[Organization]  # TODO: Mix SSO orgs with non SSO orgs
    jwks: Dict[str, List[Dict[str, Any]]]
    http_client: Union["OAuth2Client", "httpx.Client"]
    platform: "SafetyPlatformClient"
    code_verifier: str
    client_id: str
    org_name: Optional[str] = None
    stage: Optional[Stage] = Stage.development
    email: Optional[str] = None
    name: Optional[str] = None
    email_verified: bool = False

    def is_valid(self) -> bool:
        """
        Check if the authentication information is valid.

        Returns:
            bool: True if valid, False otherwise.
        """
        if os.getenv("SAFETY_DB_DIR"):
            return True

        if not self.platform:
            return False

        if self.platform.api_key:
            return True

        return bool(self.platform.token and self.email_verified)

    def refresh_from(self, info: Dict) -> None:
        """
        Refresh the authentication information from the provided info.

        Args:
            info (dict): The information to refresh from.
        """
        from safety.auth.utils import is_email_verified

        self.name = info.get("name")
        self.email = info.get("email")
        self.org_name = info.get("https://api.safetycli.com/org_name")
        self.email_verified = is_email_verified(info)  # type: ignore

    def get_auth_method(self) -> str:
        """
        Get the authentication method.

        Returns:
            str: The authentication method.
        """
        if self.platform.api_key:
            return "API Key"

        if self.platform.token:
            return "Token"

        return "None"


class XAPIKeyAuth(BaseOAuth):
    def __init__(self, api_key: str) -> None:
        """
        Initialize the XAPIKeyAuth instance.

        Args:
            api_key (str): The API key to use for authentication.
        """
        self.api_key = api_key

    def __call__(self, r: Any) -> Any:
        """
        Add the API key to the request headers.

        Args:
            r (Any): The request object.

        Returns:
            Any: The modified request object.
        """
        r.headers["X-API-Key"] = self.api_key
        return r
