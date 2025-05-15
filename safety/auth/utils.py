# type: ignore
import importlib.util
import json
import logging
from functools import lru_cache
from typing import Any, Callable, Dict, Optional, Tuple, List

import requests
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.requests_client import OAuth2Session
from requests.adapters import HTTPAdapter
from safety_schemas.models import STAGE_ID_MAPPING, Stage
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from safety.auth.constants import (
    AUTH_SERVER_URL,
)
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
    FeatureType,
    get_config_setting,
    FIREWALL_AUDIT_PYPI_PACKAGES_ENDPOINT,
)
from safety.error_handlers import output_exception
from safety.errors import (
    InvalidCredentialError,
    NetworkConnectionError,
    RequestTimeoutError,
    SafetyError,
    ServerError,
    TooManyRequestsError,
)
from safety.meta import get_meta_http_headers
from safety.models import SafetyCLI
from safety.scan.util import AuthenticationType
from safety.util import SafetyContext

LOG = logging.getLogger(__name__)


def get_keys(
    client_session: OAuth2Session, openid_config: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Retrieve the keys from the OpenID configuration.

    Args:
        client_session (OAuth2Session): The OAuth2 session.
        openid_config (Dict[str, Any]): The OpenID configuration.

    Returns:
        Optional[Dict[str, Any]]: The keys, if available.
    """
    if "jwks_uri" in openid_config:
        return client_session.get(url=openid_config["jwks_uri"], bearer=False).json()  # type: ignore
    return None


def is_email_verified(info: Dict[str, Any]) -> Optional[bool]:
    """
    Check if the email is verified.

    Args:
        info (Dict[str, Any]): The user information.

    Returns:
        bool: True
    """
    # return info.get(CLAIM_EMAIL_VERIFIED_API) or info.get(
    #     CLAIM_EMAIL_VERIFIED_AUTH_SERVER
    # )

    # Always return True to avoid email verification
    return True


def extract_detail(response: requests.Response) -> Optional[str]:
    """
    Extract the reason from an HTTP response.

    Args:
        response (requests.Response): The response.

    Returns:
        Optional[str]: The reason.
    """
    detail = None

    try:
        detail = response.json().get("detail")
    except Exception:
        LOG.debug("Failed to extract detail from response: %s", response.status_code)

    return detail


def parse_response(func: Callable) -> Callable:
    """
    Decorator to parse the response from an HTTP request.

    Args:
        func (Callable): The function to wrap.

    Returns:
        Callable: The wrapped function.
    """

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=0.2, max=8.0, exp_base=3, jitter=0.3),
        reraise=True,
        retry=retry_if_exception_type(
            (
                NetworkConnectionError,
                RequestTimeoutError,
                TooManyRequestsError,
                ServerError,
            )
        ),
        before_sleep=before_sleep_log(logging.getLogger("api_client"), logging.WARNING),
    )
    def wrapper(*args, **kwargs):
        try:
            r = func(*args, **kwargs)
        except OAuthError as e:
            LOG.exception("OAuth failed: %s", e)
            raise InvalidCredentialError(
                message="Your token authentication expired, try login again."
            )
        except requests.exceptions.ConnectionError:
            raise NetworkConnectionError()
        except requests.exceptions.Timeout:
            raise RequestTimeoutError()
        except requests.exceptions.RequestException as e:
            raise e

        # TODO: Handle content as JSON and fallback to text for all responses

        if r.status_code == 403:
            reason = extract_detail(response=r)

            raise InvalidCredentialError(
                credential="Failed authentication.", reason=reason
            )

        if r.status_code == 429:
            raise TooManyRequestsError(reason=r.text)

        if r.status_code >= 400 and r.status_code < 500:
            error_code = None
            try:
                data = r.json()
                reason = data.get("detail", "Unable to find reason.")
                error_code = data.get("error_code", None)
            except Exception:
                reason = r.reason

            raise SafetyError(message=reason, error_code=error_code)

        if r.status_code >= 500 and r.status_code < 600:
            reason = extract_detail(response=r)
            LOG.debug("ServerError %s -> Response returned: %s", r.status_code, r.text)
            raise ServerError(reason=reason)

        data = None

        try:
            data = r.json()
        except json.JSONDecodeError as e:
            raise ServerError(message=f"Bad JSON response from the server: {e}")

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

    def request(
        self,
        method: str,
        url: str,
        withhold_token: bool = False,
        auth: Optional[Tuple] = None,
        bearer: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
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
        func_timeout = (
            kwargs[TIMEOUT_KEYWARD] if TIMEOUT_KEYWARD in kwargs else REQUEST_TIMEOUT
        )

        if "headers" not in kwargs:
            kwargs["headers"] = {}

        kwargs["headers"].update(get_meta_http_headers())

        if self.api_key:
            kwargs["headers"]["X-Api-Key"] = self.api_key

        if not self.token or not bearer:
            # Fallback to no token auth
            auth = ()

        # Override proxies
        if self.proxies:
            kwargs["proxies"] = self.proxies

            if self.proxy_timeout:
                kwargs["timeout"] = int(self.proxy_timeout) / 1000

        if ("proxies" not in kwargs or not self.proxies) and self.proxy_required:
            output_exception(
                "Proxy connection is required but there is not a proxy setup.",  # type: ignore
                exit_code_output=True,
            )

        request_func = super(SafetyAuthSession, self).request
        params = {
            "method": method,
            "url": url,
            "withhold_token": withhold_token,
            "auth": auth,
        }
        params.update(kwargs)

        try:
            return request_func(**params)
        except Exception as e:
            LOG.debug("Request failed: %s", e)

            if self.proxy_required:
                output_exception(
                    f"Proxy is required but the connection failed because: {e}",  # type: ignore
                    exit_code_output=True,
                )

            if "proxies" in kwargs or self.proxies:
                params["proxies"] = {}
                params["timeout"] = func_timeout
                self.proxies = {}
                message = (
                    "The proxy configuration failed to function and was disregarded."
                )
                LOG.debug(message)
                if message not in [
                    a["message"] for a in SafetyContext.local_announcements
                ]:
                    SafetyContext.local_announcements.append(
                        {"message": message, "type": "warning", "local": True}
                    )

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

        r = self.get(url=USER_INFO_ENDPOINT)

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

        r = self.post(url=PLATFORM_API_PROJECT_CHECK_ENDPOINT, json=data)

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

        return self.get(url=PLATFORM_API_PROJECT_ENDPOINT, params=data)

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

        return self.get(url=PLATFORM_API_POLICY_ENDPOINT, params=data)

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

        return self.post(url=PLATFORM_API_PROJECT_SCAN_REQUEST_ENDPOINT, json=data)

    @parse_response
    def upload_report(self, json_report: str) -> Any:
        """
        Upload a scan report.

        Args:
            json_report (str): The JSON report.

        Returns:
            Any: The upload result.
        """

        return self.post(
            url=PLATFORM_API_PROJECT_UPLOAD_SCAN_ENDPOINT,
            data=json_report,
            headers={"Content-Type": "application/json"},
        )

    def upload_requirements(self, json_payload: str) -> Any:
        """
        Upload a scan report.
        Args:
            json_payload (str): The JSON payload to upload.
        Returns:
            Any: The result of the upload operation.
        """
        return self.post(
            url=PLATFORM_API_REQUIREMENTS_UPLOAD_SCAN_ENDPOINT,
            data=json.dumps(json_payload),
            headers={"Content-Type": "application/json"},
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

        return self.get(url=PLATFORM_API_CHECK_UPDATES_ENDPOINT, params=data)

    @parse_response
    def audit_packages(self, packages: List[str]) -> Any:
        """
        Audits packages for vulnerabilities
        Args:
            packages: list of package specifiers

        Returns:
            Any: The packages audit result.
        """
        data = {"packages": [{"package_specifier": package} for package in packages]}

        return self.post(url=FIREWALL_AUDIT_PYPI_PACKAGES_ENDPOINT, json=data)

    @parse_response
    def initialize(self) -> Any:
        """
        Initialize a run.

        Returns:
            Any: The initialization result.
        """
        try:
            response = self.get(
                url=PLATFORM_API_INITIALIZE_ENDPOINT,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            return response
        except requests.exceptions.Timeout:
            LOG.error("Auth request to initialize timed out after 5 seconds.")
        except Exception:
            LOG.exception("Exception trying to auth initialize", exc_info=True)
        return None


class S3PresignedAdapter(HTTPAdapter):
    def send(  # type: ignore
        self, request: requests.PreparedRequest, **kwargs: Any
    ) -> requests.Response:
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


@lru_cache(maxsize=1)
def is_jupyter_notebook() -> bool:
    """
    Detects if the code is running in a Jupyter notebook environment, including
    various cloud-hosted Jupyter notebooks.

    Returns:
        bool: True if the environment is identified as a Jupyter notebook (or
              equivalent cloud-based environment), False otherwise.

    Supported environments:
    - Google Colab
    - Amazon SageMaker
    - Azure Notebooks
    - Kaggle Notebooks
    - Databricks Notebooks
    - Datalore by JetBrains
    - Paperspace Gradient Notebooks
    - Classic Jupyter Notebook and JupyterLab
    """
    if (
        (
            importlib.util.find_spec("google")
            and importlib.util.find_spec("google.colab")
        )
        is not None
        or importlib.util.find_spec("sagemaker") is not None
        or importlib.util.find_spec("azureml") is not None
        or importlib.util.find_spec("kaggle") is not None
        or importlib.util.find_spec("dbutils") is not None
        or importlib.util.find_spec("datalore") is not None
        or importlib.util.find_spec("gradient") is not None
    ):
        return True

    # Detect classic Jupyter Notebook, JupyterLab, and other IPython kernel-based environments
    try:
        from IPython import get_ipython  # type: ignore

        ipython = get_ipython()
        if ipython is not None and "IPKernelApp" in ipython.config:
            return True
    except (ImportError, AttributeError, NameError):
        pass

    return False


def save_flags_config(flags: Dict[FeatureType, bool]) -> None:
    """
    Save feature flags configuration to file.

    This function attempts to save feature flags to the configuration file
    but will fail silently if unable to do so (e.g., due to permission issues
    or disk problems). Silent failure is chosen to prevent configuration issues
    from disrupting core application functionality.

    Note that if saving fails, the application will continue using existing
    or default flag values until the next restart.

    Args:
        flags: Dictionary mapping feature types to their enabled/disabled state

    The operation will be logged (with stack trace) if it fails.
    """
    import configparser

    from safety.constants import CONFIG_FILE_USER

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE_USER)

    flag_settings = {key.name.upper(): str(value) for key, value in flags.items()}

    if not config.has_section("settings"):
        config.add_section("settings")

    settings = dict(config.items("settings"))
    settings.update(flag_settings)

    for key, value in settings.items():
        config.set("settings", key, value)

    try:
        with open(CONFIG_FILE_USER, "w") as config_file:
            config.write(config_file)
    except Exception:
        LOG.exception("Unable to save flags configuration.")


def get_feature_name(feature: FeatureType, as_attr: bool = False) -> str:
    """Returns a formatted feature name with enabled suffix.

    Args:
        feature: The feature to format the name for
        as_attr: If True, formats for attribute usage (underscore),
                otherwise uses hyphen

    Returns:
        Formatted feature name string with enabled suffix
    """
    name = feature.name.lower()
    separator = "_" if as_attr else "-"
    return f"{name}{separator}enabled"


def str_to_bool(value) -> Optional[bool]:
    """Convert basic string representations to boolean."""
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        value = value.lower().strip()
        if value in ("true"):
            return True
        if value in ("false"):
            return False

    return None


def initialize(ctx: Any, refresh: bool = True) -> None:
    """
    Initializes the run by loading settings.

    Args:
        ctx (Any): The context object.
        refresh (bool): Whether to refresh settings from the server. Defaults to True.
    """
    settings = None
    current_values = {}

    if not ctx.obj:
        ctx.obj = SafetyCLI()

    for feature in FeatureType:
        value = get_config_setting(feature.name)
        if value is not None:
            current_values[feature] = str_to_bool(value)

    if refresh:
        try:
            settings = ctx.obj.auth.client.initialize()  # type: ignore
        except Exception:
            LOG.info("Unable to initialize, continue with default values.")

    if settings:
        for feature in FeatureType:
            server_value = str_to_bool(settings.get(feature.config_key))
            if server_value is not None:
                if (
                    feature not in current_values
                    or current_values[feature] != server_value
                ):
                    current_values[feature] = server_value

        save_flags_config(current_values)

    for feature, value in current_values.items():
        if value is not None:
            setattr(ctx.obj, feature.attr_name, value)
