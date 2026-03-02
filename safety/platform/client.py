"""
Safety Platform Client for API communication.

This module contains the SafetyPlatformClient which handles all communication
with the Safety Platform API, including authentication, codebase management,
policy downloads, and report uploads.
"""

from __future__ import annotations

import base64
import json
import logging
import socket
from typing import Any, Callable, Dict, List, Literal, Optional, TYPE_CHECKING, cast

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)
from safety_schemas.models import STAGE_ID_MAPPING, Stage

from safety.constants import (
    PLATFORM_API_CHECK_UPDATES_ENDPOINT,
    PLATFORM_API_INITIALIZE_ENDPOINT,
    PLATFORM_API_POLICY_ENDPOINT,
    PLATFORM_API_PROJECT_CHECK_ENDPOINT,
    PLATFORM_API_PROJECT_ENDPOINT,
    PLATFORM_API_PROJECT_SCAN_REQUEST_ENDPOINT,
    PLATFORM_API_PROJECT_UPLOAD_SCAN_ENDPOINT,
    PLATFORM_API_REQUIREMENTS_UPLOAD_SCAN_ENDPOINT,
    REQUEST_TIMEOUT,
    FIREWALL_AUDIT_PYPI_PACKAGES_ENDPOINT,
    FIREWALL_AUDIT_NPMJS_PACKAGES_ENDPOINT,
)
from safety.meta import get_meta_http_headers
from safety.utils.auth_session import AuthenticationType
from safety.util import SafetyContext
from .http_utils import parse_response

from safety.config import AuthConfig
from safety.errors import EnrollmentError, EnrollmentTransientFailure

from safety.utils.auth_session import discard_token
from safety.utils.tls_probe import probe_tls_connectivity


if TYPE_CHECKING:
    from authlib.oauth2.rfc6749 import OAuth2Token
    from safety.config.proxy import ProxyConfig
    from safety.config.tls import TLSConfig

logger = logging.getLogger(__name__)


class ApiKeyAuth(httpx.Auth):
    """
    Custom auth that uses X-Api-Key header instead of OAuth token.
    """

    def __init__(self, api_key: str):
        self.api_key = api_key

    def auth_flow(self, request):
        request.headers["X-Api-Key"] = self.api_key
        yield request


class MachineTokenAuth(httpx.Auth):
    """
    Custom auth that uses Basic Auth with machine_id:machine_token.

    Note: This is functionally identical to ``httpx.BasicAuth(machine_id,
    machine_token)``.  The dedicated class exists so that auth-type
    detection in middleware (e.g. ``http_utils.parse_response``) can
    distinguish machine-token requests from other Basic-auth uses by
    inspecting the Authorization header.
    """

    def __init__(self, machine_id: str, machine_token: str):
        self.machine_id = machine_id
        self.machine_token = machine_token

    def auth_flow(self, request):
        credentials = base64.b64encode(
            f"{self.machine_id}:{self.machine_token}".encode()
        ).decode()
        request.headers["Authorization"] = f"Basic {credentials}"
        yield request


class SafetyPlatformClient:
    """
    Synchronous client for Safety Platform API.

    Manages HTTP client creation and configuration internally, including
    proxy settings, TLS configuration, and authentication.
    """

    def __init__(
        self,
        base_url: str,
        tls_config: "TLSConfig",
        auth_server_url: str,
        openid_config_url: str,
        api_key: Optional[str] = None,
        proxy_config: Optional["ProxyConfig"] = None,
        timeout: Optional[float] = REQUEST_TIMEOUT,
        # Auth dependencies injection
        client_id: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        update_token: Optional[Callable] = None,
        scope: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        machine_id: Optional[str] = None,
        machine_token: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._machine_id = machine_id
        self._machine_token = machine_token

        if self._machine_token and not self._machine_id:
            raise ValueError("machine_id is required when machine_token is provided")
        if self._machine_id and not self._machine_token:
            raise ValueError("machine_token is required when machine_id is provided")

        self._timeout = timeout
        self._proxy_config = proxy_config
        self._tls_config = tls_config

        # Store auth dependencies
        self._client_id = client_id
        self._redirect_uri = redirect_uri
        self._update_token = update_token
        self._scope = scope
        self._code_challenge_method = code_challenge_method

        # Store auth server URLs (required)
        self._auth_server_url = auth_server_url
        self._openid_config_url = openid_config_url
        self._http_client = self._create_http_client()
        self._openid_config = None  # Cache for lazy loading
        self._jwks = None  # Cache for lazy loading JWKS

        # Initialize and test TLS configuration
        self._initialize_with_tls_fallback()

    @staticmethod
    def _get_headers() -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        headers.update(get_meta_http_headers())

        return headers

    @staticmethod
    def _build_client_kwargs(
        tls_config: "TLSConfig",
        proxy_config: Optional["ProxyConfig"] = None,
        timeout: Optional[float] = REQUEST_TIMEOUT,
    ) -> dict:
        """Build common httpx.Client constructor kwargs (TLS, headers, proxy, timeout)."""
        kwargs: dict = {
            "verify": tls_config.verify_context,
            "headers": SafetyPlatformClient._get_headers(),
            "timeout": httpx.Timeout(timeout),
            "trust_env": False,
        }
        if proxy_config:
            kwargs["proxy"] = proxy_config.endpoint.as_url()
        return kwargs

    def _create_http_client(self) -> httpx.Client:
        """
        Create HTTP client with current configuration.

        Returns:
            Configured HTTP client (httpx.Client)
        """
        client_kwargs = self._build_client_kwargs(
            self._tls_config, self._proxy_config, self._timeout
        )

        # Create the appropriate client type
        if self._api_key:
            auth = ApiKeyAuth(self._api_key)
            return httpx.Client(auth=auth, **client_kwargs)
        elif self._machine_token:
            assert (
                self._machine_id is not None
            )  # machine_id required with machine_token
            auth = MachineTokenAuth(self._machine_id, self._machine_token)
            return httpx.Client(auth=auth, **client_kwargs)
        else:
            # Use injected auth dependencies
            if not all(
                [self._client_id, self._redirect_uri, self._update_token, self._scope]
            ):
                raise ValueError(
                    "OAuth2 auth dependencies must be provided when not using API key"
                )

            return cast(
                httpx.Client,
                OAuth2Client(
                    client_id=self._client_id,
                    code_challenge_method=self._code_challenge_method,
                    redirect_uri=self._redirect_uri,
                    update_token=self._update_token,
                    scope=self._scope,
                    **client_kwargs,
                ),
            )

    def _initialize_with_tls_fallback(self) -> None:
        """Initialize the client by testing TLS with a lightweight HEAD probe.

        Uses a HEAD request to verify TLS connectivity. If SSL error occurs
        with the default (certifi) trust store, falls back to the system trust
        store and recreates the HTTP client. OpenID config is fetched lazily
        on first use, not during initialization.

        Raises:
            SSLCertificateError: If TLS cannot be established.
            Exception: On non-TLS errors (DNS, timeout, refused, etc.).
        """
        try:
            result = probe_tls_connectivity(
                probe_url=self._openid_config_url,
                tls_config=self._tls_config,
                proxy_config=self._proxy_config,
                save_preference=True,
            )
        except Exception as e:
            logger.warning("Failed to initialize SafetyPlatformClient: %s", e)
            raise

        if result.fell_back:
            logger.warning("Recreating HTTP client with system TLS trust store")
            self._tls_config = result.tls_config
            self._http_client.close()
            self._http_client = self._create_http_client()

        logger.debug("TLS configuration verified successfully")

    @property
    def http_client(self) -> httpx.Client:
        """
        The HTTP client configured for this invocation's auth path.

        Pre-configured with authentication (API key, machine token, or OAuth2),
        TLS settings, proxy configuration, and appropriate headers. On the OAuth2
        path this is an ``OAuth2Client`` (supports login flows AND API calls).

        Returns:
            httpx.Client: The configured HTTP client.
        """
        return self._http_client

    @property
    def api_key(self) -> Optional[str]:
        return self._api_key

    @property
    def has_machine_token(self) -> bool:
        """Whether this client is using machine token authentication."""
        return bool(self._machine_token)

    @property
    def machine_id(self) -> Optional[str]:
        """The machine ID, if using machine token auth."""
        return self._machine_id

    @property
    def token(self) -> Optional["OAuth2Token"]:
        if not isinstance(self._http_client, OAuth2Client):
            return None

        return self._http_client.token

    def load_auth_token_from_storage(self, jwks: Dict[str, Any]) -> None:
        """
        Loads the authentication token from the storage.

        Args:
            jwks (Dict[str, Any]): The JWKS.
        """
        if self._machine_token:
            return

        auth_config = AuthConfig.from_storage()

        if isinstance(self._http_client, OAuth2Client) and auth_config:
            try:
                self._http_client.token = auth_config.to_token(jwks=jwks)
            except Exception as e:
                logger.error(
                    "Failed to load auth token from storage", extra={"error": str(e)}
                )
                discard_token(self._http_client)

    def get_credential(self) -> Optional[str]:
        """
        Get the current authentication credential.

        Returns:
            Optional[str]: The API key, token, or None.
        """
        if self.api_key:
            return self.api_key

        if self._machine_token:
            return self._machine_id

        if isinstance(self._http_client, OAuth2Client) and self._http_client.token:
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

        if self._machine_token:
            return AuthenticationType.machine_token

        if self.token:
            return AuthenticationType.token

        return AuthenticationType.none

    def get_openid_config(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get OpenID config, fetching and caching if needed.

        Args:
            force_refresh (bool): If True, bypass cache and fetch fresh config.

        Returns:
            Dict[str, Any]: The OpenID configuration.
        """
        if self._openid_config is None or force_refresh:
            self._openid_config = self._fetch_openid_config()
        return self._openid_config

    @parse_response
    def _fetch_openid_config(self) -> Any:
        """
        Fetch the OpenID configuration from the authorization server.

        Returns:
            Any: The OpenID configuration.
        """

        return self._http_client.get(url=self._openid_config_url, auth=None)

    def get_jwks(self, force_refresh: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get JWKS, fetching and caching if needed.

        Args:
            force_refresh (bool): If True, bypass cache and fetch fresh JWKS.

        Returns:
            Dict[str, List[Dict[str, Any]]]: The keys.
        """
        if self._jwks is None or force_refresh:
            self._jwks = self._fetch_jwks()
        return self._jwks

    @parse_response  # type: ignore
    def _fetch_jwks(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Fetch the JWKS from the OpenID configuration.

        Returns:
            Dict[str, List[Dict[str, Any]]]: The keys.
        """
        openid_config = self.get_openid_config()  # Use lazy-loaded config
        return self._http_client.get(url=openid_config["jwks_uri"], auth=None)  # type: ignore

    @parse_response
    def fetch_user_info(self) -> Any:
        """
        Fetch user information from the authorization server.

        Returns:
            Any: The user information.
        """
        USER_INFO_ENDPOINT = f"{self._auth_server_url}/userinfo"

        r = self._http_client.get(url=USER_INFO_ENDPOINT)

        return r

    @parse_response
    def check_project(
        self,
        scan_stage: str,
        safety_source: str,
        project_slug: Optional[str] = None,
        git_origin: Optional[str] = None,
        project_slug_source: Optional[str] = None,
    ) -> Any:
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

        data = {
            "scan_stage": scan_stage,
            "safety_source": safety_source,
            "project_slug": project_slug,
            "project_slug_source": project_slug_source,
            "git_origin": git_origin,
        }

        r = self._http_client.post(url=PLATFORM_API_PROJECT_CHECK_ENDPOINT, json=data)

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

        return self._http_client.get(url=PLATFORM_API_PROJECT_ENDPOINT, params=data)

    @parse_response
    def download_policy(
        self, project_id: Optional[str], stage: Stage, branch: Optional[str]
    ) -> Any:
        """
        Download the project policy.

        Args:
            project_id (Optional[str]): The project ID.
            stage (Stage): The stage.
            branch (Optional[str]): The branch.

        Returns:
            Any: The policy data.
        """
        data = {
            "project": project_id,
            "stage": STAGE_ID_MAPPING[stage],
            "branch": branch,
        }

        return self._http_client.get(url=PLATFORM_API_POLICY_ENDPOINT, params=data)

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

        return self._http_client.post(
            url=PLATFORM_API_PROJECT_SCAN_REQUEST_ENDPOINT, json=data
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

        return self._http_client.post(
            url=PLATFORM_API_PROJECT_UPLOAD_SCAN_ENDPOINT,
            content=json_report,
        )

    def upload_requirements(self, json_payload: dict) -> Any:
        """
        Upload a scan report.
        Args:
            json_payload (dict): The JSON payload to upload.
        Returns:
            Any: The result of the upload operation.
        """
        return self._http_client.post(
            url=PLATFORM_API_REQUIREMENTS_UPLOAD_SCAN_ENDPOINT,
            json=json_payload,
        )

    @parse_response
    def check_updates(
        self,
        version: int,
        safety_version: Optional[str] = None,
        python_version: Optional[str] = None,
        os_type: Optional[str] = None,
        os_release: Optional[str] = None,
        os_description: Optional[str] = None,
    ) -> Any:
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
        data = {
            "version": version,
            "safety_version": safety_version,
            "python_version": python_version,
            "os_type": os_type,
            "os_release": os_release,
            "os_description": os_description,
        }

        return self._http_client.get(
            url=PLATFORM_API_CHECK_UPDATES_ENDPOINT, params=data
        )

    @parse_response
    def audit_packages(
        self, packages: List[str], ecosystem: Literal["pypi", "npmjs"]
    ) -> Any:
        """
        Audits packages for vulnerabilities
        Args:
            packages: list of package specifiers
            ecosystem: the ecosystem to audit

        Returns:
            Any: The packages audit result.
        """
        url = (
            FIREWALL_AUDIT_NPMJS_PACKAGES_ENDPOINT
            if ecosystem == "npmjs"
            else FIREWALL_AUDIT_PYPI_PACKAGES_ENDPOINT
        )

        data = {"packages": [{"package_specifier": package} for package in packages]}

        return self._http_client.post(url=url, json=data)

    @parse_response
    def initialize(self) -> Any:
        """
        Initialize a run.

        Returns:
            Any: The initialization result.
        """
        return self._http_client.get(
            url=PLATFORM_API_INITIALIZE_ENDPOINT,
            timeout=5,
        )

    # ------------------------------------------------------------------
    # Enrollment
    # ------------------------------------------------------------------

    def enroll(
        self,
        enrollment_base_url: str,
        enrollment_key: str,
        machine_id: str,
        force: bool = False,
        org_legacy_uuid: str = "",
    ) -> dict:
        """Enroll a machine with the Safety Platform.

        Uses the instance's already-configured HTTP client (TLS and proxy
        were probed during ``__init__``), then retries the POST up to 3
        times on transient network errors.

        Args:
            enrollment_base_url: Base URL for the enrollment API
                (typically ``SAFETY_PLATFORM_V2_URL``).
            enrollment_key: The enrollment key provided by the MDM administrator.
            machine_id: The machine identity to enroll.
            force: When True, request re-enrollment for an already-enrolled machine.
            org_legacy_uuid: When non-empty, the org UUID of the authenticated user
                is sent to the server to detect cross-org enrollment attempts.

        Returns:
            dict with keys 'machine_id' and 'machine_token' on success.

        Raises:
            EnrollmentError: On 401 (invalid key), 403 (org mismatch),
                409 (already enrolled), or other 4xx failures.
            EnrollmentTransientFailure: On 5xx server errors.
            httpx.ConnectError: On network errors (retried, then re-raised).
            httpx.TimeoutException: On timeouts (retried, then re-raised).
        """
        return self._enroll_post(
            self._http_client,
            enrollment_base_url,
            enrollment_key,
            machine_id,
            force,
            org_legacy_uuid,
        )

    @staticmethod
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=0.5, max=8.0, exp_base=3, jitter=0.3),
        reraise=True,
        retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    def _enroll_post(
        client: httpx.Client,
        base_url: str,
        enrollment_key: str,
        machine_id: str,
        force: bool,
        org_legacy_uuid: str = "",
    ) -> dict:
        """POST enrollment request with tenacity retry on transient errors."""
        # Lazy import: safety.auth.constants -> safety.auth -> safety.auth.cli_utils
        # -> safety.platform (circular)
        from safety.auth.constants import ENROLLMENT_ENDPOINT

        url = f"{base_url}{ENROLLMENT_ENDPOINT}"
        hostname = socket.gethostname()

        payload: dict = {"machine_id": machine_id, "hostname": hostname}
        if force:
            payload["force"] = True
        if org_legacy_uuid:
            payload["org_legacy_uuid"] = org_legacy_uuid

        response = client.post(
            url,
            json=payload,
            auth=httpx.BasicAuth(enrollment_key, ""),
            follow_redirects=True,
        )
        return SafetyPlatformClient._parse_enrollment_response(response, force)

    @staticmethod
    def _parse_enrollment_response(response: httpx.Response, force: bool) -> dict:
        """Parse the enrollment HTTP response.

        NOT decorated with @parse_response — enrollment has its own
        error semantics distinct from the standard platform API.
        """
        if response.status_code in (200, 201):
            return response.json()

        if response.status_code == 401:
            raise EnrollmentError("Invalid or expired enrollment key")

        if response.status_code == 403:
            try:
                detail = response.json().get("detail", "")
            except (json.JSONDecodeError, ValueError, AttributeError):
                detail = ""
            if detail == "Organization identity mismatch":
                raise EnrollmentError(
                    "You are trying to enroll this device into a different "
                    "organization from its currently authenticated Safety user. "
                    "Please either logout of Safety (`safety auth logout`) or "
                    "ensure your enrollment key is for the same organization "
                    "as your user account."
                )
            raise EnrollmentError(
                f"Enrollment forbidden (HTTP 403): {detail or response.text}"
            )

        if response.status_code == 409:
            if force:
                raise EnrollmentError(
                    "Machine is already enrolled and the server rejected re-enrollment. "
                    "Contact your administrator."
                )
            raise EnrollmentError(
                "Machine is already enrolled on the server. Use --force to re-enroll."
            )

        # 5xx server errors are transient — MDM orchestrators should retry
        if response.status_code >= 500:
            try:
                detail = response.json().get("detail", response.text)
            except (json.JSONDecodeError, ValueError, AttributeError):
                detail = response.text
            raise EnrollmentTransientFailure(
                f"Enrollment failed (HTTP {response.status_code}): {detail}"
            )

        # Other error (4xx not handled above)
        try:
            detail = response.json().get("detail", response.text)
        except (json.JSONDecodeError, ValueError, AttributeError):
            detail = response.text

        raise EnrollmentError(
            f"Enrollment failed (HTTP {response.status_code}): {detail}"
        )
