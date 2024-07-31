import json
import logging
from typing import Any, Optional, Dict, Callable, Tuple
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client.errors import OAuthError
import requests
from requests.adapters import HTTPAdapter

from safety.auth.constants import AUTH_SERVER_URL, CLAIM_EMAIL_VERIFIED_API, \
    CLAIM_EMAIL_VERIFIED_AUTH_SERVER
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


def get_keys(client_session: OAuth2Session, openid_config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Retrieve the keys from the OpenID configuration.

    Args:
        client_session (OAuth2Session): The OAuth2 session.
        openid_config (Dict[str, Any]): The OpenID configuration.

    Returns:
        Optional[Dict[str, Any]]: The keys, if available.
    """
    if "jwks_uri" in openid_config:
        return client_session.get(url=openid_config["jwks_uri"], bearer=False).json()
    return None


def is_email_verified(info: Dict[str, Any]) -> Optional[bool]:
    """
    Check if the email is verified.

    Args:
        info (Dict[str, Any]): The user information.

    Returns:
        bool: True if the email is verified, False otherwise.
    """
    return info.get(CLAIM_EMAIL_VERIFIED_API) or info.get(CLAIM_EMAIL_VERIFIED_AUTH_SERVER)


def parse_response(func: Callable) -> Callable:
    """
    Decorator to parse the response from an HTTP request.

    Args:
        func (Callable): The function to wrap.

    Returns:
        Callable: The wrapped function.
    """
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

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Initialize the SafetyAuthSession.

        Args:
            *args (Any): Positional arguments for the parent class.
            **kwargs (Any): Keyword arguments for the parent class.
        """
        super().__init__(*args, **kwargs)
        self.proxy_required: bool = False
        self.proxy_timeout: Optional[int] = None
        self.api_key = None

    def get_credential(self) -> Optional[str]:
        """
        Get the current authentication credential.

        Returns:
            Optional[str]: The API key, token, or None.
        """
        if self.api_key:
            return self.api_key

        if self.token:
            return SafetyContext().account

        return None

    def is_using_auth_credentials(self) -> bool:
        """
        Check if the session is using authentication credentials.

        This does NOT check if the client is authenticated.

        Returns:
            bool: True if using authentication credentials, False otherwise.
        """
        return self.get_authentication_type() != AuthenticationType.none

    def get_authentication_type(self) -> AuthenticationType:
        """
        Get the type of authentication being used.

        Returns:
            AuthenticationType: The type of authentication.
        """
        if self.api_key:
            return AuthenticationType.api_key

        if self.token:
            return AuthenticationType.token

        return AuthenticationType.none

    def request(self, method: str, url: str, withhold_token: bool = False, auth: Optional[Tuple] = None, bearer: bool = True, **kwargs: Any) -> requests.Response:
        """
        Make an HTTP request with the appropriate authentication.

        Use the right auth parameter for Safety supported auth types.

        Args:
            method (str): The HTTP method.
            url (str): The URL to request.
            withhold_token (bool): Whether to withhold the token.
            auth (Optional[Tuple]): The authentication tuple.
            bearer (bool): Whether to use bearer authentication.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            requests.Response: The HTTP response.

        Raises:
            Exception: If the request fails.
        """
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
        """
        Fetch user information from the authorization server.

        Returns:
            Any: The user information.
        """
        USER_INFO_ENDPOINT = f"{AUTH_SERVER_URL}/userinfo"

        r = self.get(
            url=USER_INFO_ENDPOINT
        )

        return r

    @parse_response
    def check_project(self, scan_stage: str, safety_source: str,
                      project_slug: Optional[str] = None, git_origin: Optional[str] = None,
                      project_slug_source: Optional[str] = None) -> Any:
        """
        Check project information.

        Args:
            scan_stage (str): The scan stage.
            safety_source (str): The safety source.
            project_slug (Optional[str]): The project slug.
            git_origin (Optional[str]): The git origin.
            project_slug_source (Optional[str]): The project slug source.

        Returns:
            Any: The project information.
        """

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
        """
        Get project information.

        Args:
            project_id (str): The project ID.

        Returns:
            Any: The project information.
        """
        data = {"project": project_id}

        return self.get(
            url=PLATFORM_API_PROJECT_ENDPOINT,
            params=data
        )

    @parse_response
    def download_policy(self, project_id: Optional[str], stage: Stage, branch: Optional[str]) -> Any:
        """
        Download the project policy.

        Args:
            project_id (Optional[str]): The project ID.
            stage (Stage): The stage.
            branch (Optional[str]): The branch.

        Returns:
            Any: The policy data.
        """
        data = {"project": project_id, "stage": STAGE_ID_MAPPING[stage], "branch": branch}

        return self.get(
            url=PLATFORM_API_POLICY_ENDPOINT,
            params=data
        )


    @parse_response
    def project_scan_request(self, project_id: str) -> Any:
        """
        Request a project scan.

        Args:
            project_id (str): The project ID.

        Returns:
            Any: The scan request result.
        """
        data = {"project_id": project_id}

        return self.post(
            url=PLATFORM_API_PROJECT_SCAN_REQUEST_ENDPOINT,
            json=data
        )


    @parse_response
    def upload_report(self, json_report: str) -> Any:
        """
        Upload a scan report.

        Args:
            json_report (str): The JSON report.

        Returns:
            Any: The upload result.
        """

        headers = {
            "Content-Type": "application/json"
        }

        return self.post(
            url=PLATFORM_API_PROJECT_UPLOAD_SCAN_ENDPOINT,
            data=json_report,
            headers=headers
        )


    @parse_response
    def check_updates(self, version: int, safety_version: Optional[str] = None, python_version: Optional[str] = None, os_type: Optional[str] = None, os_release: Optional[str] = None, os_description: Optional[str] = None) -> Any:
        """
        Check for updates.

        Args:
            version (int): The version.
            safety_version (Optional[str]): The Safety version.
            python_version (Optional[str]): The Python version.
            os_type (Optional[str]): The OS type.
            os_release (Optional[str]): The OS release.
            os_description (Optional[str]): The OS description.

        Returns:
            Any: The update check result.
        """
        data = {"version": version,
                "safety_version": safety_version,
                "python_version": python_version,
                "os_type": os_type,
                "os_release": os_release,
                "os_description": os_description}

        return self.get(
            url=PLATFORM_API_CHECK_UPDATES_ENDPOINT,
            params=data
        )


    @parse_response
    def initialize_scan(self) -> Any:
        """
        Initialize a scan.

        Returns:
            Any: The initialization result.
        """
        return self.get(url=PLATFORM_API_INITIALIZE_SCAN_ENDPOINT, timeout=2)

class S3PresignedAdapter(HTTPAdapter):
    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        """
        Send a request, removing the Authorization header.

        Args:
            request (requests.PreparedRequest): The prepared request.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            requests.Response: The response.
        """
        request.headers.pop("Authorization", None)
        return super().send(request, **kwargs)
