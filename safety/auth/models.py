from dataclasses import dataclass
from typing import Any, Optional

from authlib.integrations.base_client import BaseOAuth

from safety_schemas.models import Stage

@dataclass
class Organization:
    id: str
    name: str

    def to_dict(self):
        return {'id': self.id, 'name': self.name}

@dataclass
class Auth:
    org: Optional[Organization]
    keys: Any
    client: Any
    code_verifier: str
    client_id: str
    stage: Optional[Stage] = Stage.development
    email: Optional[str] = None
    name: Optional[str] = None
    email_verified: bool = False

    def is_valid(self) -> bool:
        if not self.client:
            return False

        if self.client.api_key:
            return True

        return bool(self.client.token and self.email_verified)

    def refresh_from(self, info):
        self.name = info.get("name")
        self.email = info.get("email")
        self.email_verified = info.get("email_verified", False)

class XAPIKeyAuth(BaseOAuth):
    def __init__(self, api_key):
        self.api_key = api_key

    def __call__(self, r):
        r.headers['X-API-Key'] = self.api_key
        return r
