import json
import logging
from typing import Any, Optional
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client.errors import OAuthError
import requests
from requests.adapters import HTTPAdapter
from safety.auth.constants import AUTH_SERVER_URL
from safety.auth.main import get_auth_info, get_token_data
from safety.constants import PLATFORM_API_CHECK_UPDATES_ENDPOINT, PLATFORM_API_INITIALIZE_SCAN_ENDPOINT, PLATFORM_API_POLICY_ENDPOINT, \
    PLATFORM_API_PROJECT_CHECK_ENDPOINT, PLATFORM_API_PROJECT_ENDPOINT, PLATFORM_API_PROJECT_SCAN_REQUEST_ENDPOINT, \
        PLATFORM_API_PROJECT_UPLOAD_SCAN_ENDPOINT, REQUEST_TIMEOUT
from safety.scan.util import AuthenticationType

from safety.util import SafetyContext, output_exception
from safety_schemas.models import STAGE_ID_MAPPING, Stage
from safety.errors import InvalidCredentialError, NetworkConnectionError, \
    RequestTimeoutError, ServerError, TooManyRequestsError, SafetyError

LOG = logging.getLogger(__name__)

def get_keys(client_session, openid_config):
    if "jwks_uri" in openid_config:
        return client_session.get(url=openid_config["jwks_uri"], bearer=False).json()
    return None

def parse_response(func):
    def wrapper(*args, **kwargs):
        try:
            r = func(*args, **kwargs)
        except OAuthError as e:
            LOG.exception('OAuth failed: %s', e)
            raise InvalidCredentialError(message="Your token authentication expired, try login again.")
        except requests.exceptions.ConnectionError:
            raise NetworkConnectionError()
        except requests.exceptions.Timeout:
            raise RequestTimeoutError()
        except requests.exceptions.RequestException as e:
            raise e

        if r.status_code == 403:
            raise InvalidCredentialError(credential="Failed authentication.", 
                                               reason=r.text)

        if r.status_code == 429:
            raise TooManyRequestsError(reason=r.text)
        
        if r.status_code >= 400 and r.status_code < 500:
            error_code = None
            try:
                data = r.json()
                reason = data.get('detail', "Unable to find reason.")
                error_code = data.get("error_code", None)
            except Exception as e:
                reason = r.reason

            raise SafetyError(message=reason, error_code=error_code)

        if r.status_code >= 500:
            raise ServerError(reason=f"{r.reason} - {r.text}")

        data = None

        try:
            data = r.json()
        except json.JSONDecodeError as e:
            raise SafetyError(message=f"Bad JSON response: {e}")
                
        return data

    return wrapper

class SafetyAuthSession(OAuth2Session):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.proxy_required: bool = False
        self.proxy_timeout: Optional[int] = None
        self.api_key = None

    def get_credential(self) -> Optional[str]:
        if self.api_key:
            return self.api_key
        
        if self.token:
            return SafetyContext().account
        
        return None
    
    def is_using_auth_credentials(self) -> bool:
        """This does NOT check if the client is authenticated"""
        return self.get_authentication_type() != AuthenticationType.none

    def get_authentication_type(self) -> AuthenticationType:
        if self.api_key:
            return AuthenticationType.api_key
        
        if self.token:
            return AuthenticationType.token
        
        return AuthenticationType.none

    def request(self, method, url, withhold_token=False, auth=None, bearer=True, **kwargs):
        """Use the right auth parameter for Safety supported auth types"""
        # By default use the token_auth
        TIMEOUT_KEYWARD = "timeout"
        func_timeout = kwargs[TIMEOUT_KEYWARD] if TIMEOUT_KEYWARD in kwargs else REQUEST_TIMEOUT

        if self.api_key:
            key_header = {"X-Api-Key": self.api_key}
            if not "headers" in kwargs:
                kwargs["headers"] = key_header
            else:
                kwargs["headers"]["X-Api-Key"] = self.api_key
        
        if not self.token or not bearer:
            # Fallback to no token auth
            auth = ()


        # Override proxies
        if self.proxies:
            kwargs['proxies'] = self.proxies
            
            if self.proxy_timeout:
                kwargs['timeout'] = int(self.proxy_timeout) / 1000

        if ("proxies" not in kwargs or not self.proxies) and self.proxy_required:
            output_exception("Proxy connection is required but there is not a proxy setup.", exit_code_output=True)

        request_func = super(SafetyAuthSession, self).request
        params = {
            'method': method,
            'url': url,
            'withhold_token': withhold_token,
            'auth': auth,            
        }
        params.update(kwargs)

        try:
            return request_func(**params)
        except Exception as e:
            LOG.debug('Request failed: %s', e)

            if self.proxy_required:
                output_exception(f"Proxy is required but the connection failed because: {e}", exit_code_output=True)

            if ("proxies" in kwargs or self.proxies):
                params["proxies"] = {}
                params['timeout'] = func_timeout
                self.proxies = {}
                message = "The proxy configuration failed to function and was disregarded."
                LOG.debug(message)
                if message not in [a['message'] for a in SafetyContext.local_announcements]:
                    SafetyContext.local_announcements.append({'message': message, 'type': 'warning', 'local': True})
                
                return request_func(**params)
            
            raise e

    @parse_response
    def fetch_user_info(self) -> Any:
        USER_INFO_ENDPOINT = f"{AUTH_SERVER_URL}/userinfo"

        r = self.get(
            url=USER_INFO_ENDPOINT
        )

        return r

    @parse_response
    def check_project(self, scan_stage: str, safety_source: str, 
                      project_slug: Optional[str] = None, git_origin: Optional[str] = None,
                      project_slug_source: Optional[str] = None) -> Any:

        data = {"scan_stage": scan_stage, "safety_source": safety_source, 
                "project_slug": project_slug, 
                "project_slug_source": project_slug_source, 
                "git_origin": git_origin}

        r = self.post(
                url=PLATFORM_API_PROJECT_CHECK_ENDPOINT,
                json=data
            )

        return r
    
    @parse_response
    def project(self, project_id: str) -> Any:
        data = {"project": project_id}

        r = self.get(
            url=PLATFORM_API_PROJECT_ENDPOINT,
            params=data
        )

        return r

    @parse_response
    def download_policy(self, project_id: Optional[str], stage: Stage, branch: Optional[str]) -> Any:
        data = {"project": project_id, "stage": STAGE_ID_MAPPING[stage], "branch": branch}

        r = self.get(
            url=PLATFORM_API_POLICY_ENDPOINT,
            params=data
        )

        return r
    
    @parse_response
    def project_scan_request(self, project_id: str) -> Any:
        data = {"project_id": project_id}

        r = self.post(
            url=PLATFORM_API_PROJECT_SCAN_REQUEST_ENDPOINT,
            json=data
        )

        return r
    
    @parse_response
    def upload_report(self, json_report: str) -> Any:

        headers = {
            "Content-Type": "application/json"
        }        

        r = self.post(
            url=PLATFORM_API_PROJECT_UPLOAD_SCAN_ENDPOINT,
            data=json_report,
            headers=headers
        )

        return r
    
    @parse_response
    def check_updates(self, version: int, safety_version=None,
                                                     python_version=None,
                                                     os_type=None,
                                                     os_release=None,
                                                     os_description=None) -> Any:
        data = {"version": version, 
                "safety_version": safety_version,
                "python_version": python_version,
                "os_type": os_type,
                "os_release": os_release,
                "os_description": os_description}

        r = self.get(
            url=PLATFORM_API_CHECK_UPDATES_ENDPOINT,
            params=data
        )

        return r

    @parse_response
    def initialize_scan(self) -> Any:
        return self.get(url=PLATFORM_API_INITIALIZE_SCAN_ENDPOINT, timeout=2)

class S3PresignedAdapter(HTTPAdapter):
    def send(self, request, **kwargs):
        request.headers.pop("Authorization", None)
        return super().send(request, **kwargs)
