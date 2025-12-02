"""
Safety Platform Client for API communication.

This module contains the SafetyPlatformClient which handles all communication
with the Safety Platform API, including authentication, codebase management,
policy downloads, and report uploads.
"""

import logging
from typing import Any, Callable, Dict, List, Literal, Optional, Union, TYPE_CHECKING

import httpx
from authlib.integrations.httpx_client import OAuth2Client
from safety_schemas.models import STAGE_ID_MAPPING, Stage
from safety.errors import SSLCertificateError

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
    CONFIG,
)
from safety.meta import get_meta_http_headers
from safety.utils.auth_session import AuthenticationType
from safety.util import SafetyContext
from .http_utils import parse_response

from safety.config import AuthConfig, get_tls_config

from safety.utils.auth_session import discard_token
from configparser import ConfigParser


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
    ):
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
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

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        headers.update(get_meta_http_headers())

        return headers

    def _create_http_client(self) -> Union[httpx.Client, OAuth2Client]:
        """
        Create HTTP client with current configuration.

        Returns:
            Configured HTTP client (httpx.Client or OAuth2Client)
        """
        # Build client configuration
        client_kwargs = {
            "verify": self._tls_config.verify_context,
            "headers": self._get_headers(),
            "timeout": httpx.Timeout(self._timeout),
            "trust_env": False,
        }

        if self._proxy_config:
            client_kwargs["proxy"] = self._proxy_config.endpoint.as_url()

        # Create the appropriate client type
        if self._api_key:
            auth = ApiKeyAuth(self._api_key)
            return httpx.Client(auth=auth, **client_kwargs)
        else:
            # Use injected auth dependencies
            if not all(
                [self._client_id, self._redirect_uri, self._update_token, self._scope]
            ):
                raise ValueError(
                    "OAuth2 auth dependencies must be provided when not using API key"
                )

            return OAuth2Client(
                client_id=self._client_id,
                code_challenge_method=self._code_challenge_method,
                redirect_uri=self._redirect_uri,
                update_token=self._update_token,
                scope=self._scope,
                **client_kwargs,
            )

    def _initialize_with_tls_fallback(self) -> None:
        """
        Initialize the client by testing TLS configuration.

        Attempts to fetch OpenID config to verify TLS works. If SSL error occurs
        and we're using default (certifi) TLS, falls back to system trust store.

        Raises:
            Exception: If neither default nor system TLS configuration works.
        """
        try:
            # Test TLS by fetching OpenID config
            self.get_openid_config()
            logger.debug("TLS configuration verified successfully")
        except SSLCertificateError as e:
            logger.warning(f"TLS initialization failed with SSL error: {e}")

            # Only attempt fallback if using default (certifi) TLS
            if self._tls_config.mode == "default":
                logger.warning(
                    "Attempting TLS fallback to system trust store during initialization"
                )
                try:
                    self._recreate_client_with_system_tls()
                    # Test again with system TLS
                    self._openid_config = None  # Clear cache to force fresh fetch
                    self.get_openid_config()
                    # Save the successful fallback preference
                    self._save_tls_fallback_preference()
                    logger.info(
                        "TLS initialization successful after fallback to system trust store"
                    )
                except Exception as fallback_error:
                    logger.error(
                        f"TLS fallback failed during initialization: {fallback_error}"
                    )
                    raise Exception(f"TLS initialization failed: {e}") from e
            else:
                logger.error("No TLS fallback available, initialization failed")
                raise Exception(f"TLS initialization failed: {e}") from e
        except Exception as e:
            logger.warning(f"Failed to initialize SafetyPlatformClient: {e}")
            raise

    def _recreate_client_with_system_tls(self) -> None:
        """
        Recreate HTTP client using system TLS trust store as fallback.

        This method is called when TLS verification fails with the default
        configuration, attempting to use the system's trust store instead.
        """
        logger.warning("Recreating HTTP client with system TLS trust store")

        # Update TLS config to use system context
        self._tls_config = get_tls_config(mode="system")

        # Recreate the HTTP client with new TLS config
        old_client = self._http_client
        self._http_client = self._create_http_client()

        # Close old client
        if hasattr(old_client, "close"):
            old_client.close()

        logger.info("Successfully recreated HTTP client with system TLS")

    def _save_tls_fallback_preference(self) -> None:
        """
        Save successful system trust store fallback to config file.
        """
        try:
            config = ConfigParser()
            config.read(CONFIG)

            if not config.has_section("tls"):
                config.add_section("tls")

            config.set("tls", "mode", "system")

            # Create parent directory if it doesn't exist
            CONFIG.parent.mkdir(parents=True, exist_ok=True)

            with open(CONFIG, "w") as configfile:
                config.write(configfile)

            logger.info(
                "Saved system trust store preference to config",
                extra={"config_path": str(CONFIG)},
            )
        except Exception as e:
            logger.warning(
                "Failed to save TLS fallback preference",
                extra={"config_path": str(CONFIG), "error": str(e)},
            )

    @property
    def api_key(self) -> Optional[str]:
        return self._api_key

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

        auth_config = AuthConfig.from_storage(jwks=jwks)

        if isinstance(self._http_client, OAuth2Client) and auth_config:
            try:
                self._http_client.token = auth_config.to_token(jwks=jwks)
            except Exception as e:
                print(e)
                discard_token(self._http_client)

    def get_credential(self) -> Optional[str]:
        """
        Get the current authentication credential.

        Returns:
            Optional[str]: The API key, token, or None.
        """
        if self.api_key:
            return self.api_key

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
        try:
            response = self._http_client.get(
                url=PLATFORM_API_INITIALIZE_ENDPOINT,
                # headers={"Content-Type": "application/json"},
                timeout=5,
            )
            return response
        except httpx.TimeoutException:
            logger.error("Auth request to initialize timed out after 5 seconds.")
        except Exception:
            logger.exception("Exception trying to auth initialize", exc_info=True)
        return None
