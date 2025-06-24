# -*- coding: utf-8 -*-
import configparser
import os
from enum import Enum
from pathlib import Path
from typing import Optional

from safety.meta import get_version

JSON_SCHEMA_VERSION = "2.0.0"

# TODO fix this
OPEN_MIRRORS = [
    f"https://pyup.io/aws/safety/free/{JSON_SCHEMA_VERSION}/",
]

DIR_NAME = ".safety"


def get_system_dir() -> Path:
    """
    Get the system directory for the safety configuration.

    Returns:
        Path: The system directory path.
    """
    import os
    import sys

    raw_dir = os.getenv("SAFETY_SYSTEM_CONFIG_PATH")
    app_data = os.environ.get("ALLUSERSPROFILE", None)

    if not raw_dir:
        if sys.platform.startswith("win") and app_data:
            raw_dir = app_data
        elif sys.platform.startswith("darwin"):
            raw_dir = "/Library/Application Support"
        elif sys.platform.startswith("linux"):
            raw_dir = "/etc"
        else:
            raw_dir = "/"

    return Path(raw_dir, DIR_NAME)


def get_user_dir() -> Path:
    """
    Get the user directory for the safety configuration.

    Returns:
        Path: The user directory path.
    """
    path = Path("~", DIR_NAME).expanduser()
    return path


USER_CONFIG_DIR = get_user_dir()
SYSTEM_CONFIG_DIR = get_system_dir()

CACHE_FILE_DIR = USER_CONFIG_DIR / f"{JSON_SCHEMA_VERSION.replace('.', '')}"
DB_CACHE_FILE = CACHE_FILE_DIR / "cache.json"

CONFIG_FILE_NAME = "config.ini"
CONFIG_FILE_SYSTEM = SYSTEM_CONFIG_DIR / CONFIG_FILE_NAME if SYSTEM_CONFIG_DIR else None
CONFIG_FILE_USER = USER_CONFIG_DIR / CONFIG_FILE_NAME

CONFIG = (
    CONFIG_FILE_SYSTEM
    if CONFIG_FILE_SYSTEM and CONFIG_FILE_SYSTEM.exists()
    else CONFIG_FILE_USER
)

SAFETY_POLICY_FILE_NAME = ".safety-policy.yml"
SYSTEM_POLICY_FILE = SYSTEM_CONFIG_DIR / SAFETY_POLICY_FILE_NAME
USER_POLICY_FILE = USER_CONFIG_DIR / SAFETY_POLICY_FILE_NAME

DEFAULT_DOMAIN = "safetycli.com"
DEFAULT_EMAIL = f"support@{DEFAULT_DOMAIN}"


class URLSettings(Enum):
    PLATFORM_API_BASE_URL = f"https://platform.{DEFAULT_DOMAIN}/cli/api/v1"
    DATA_API_BASE_URL = f"https://data.{DEFAULT_DOMAIN}/api/v1/safety/"
    CLIENT_ID = "AWnwFBMr9DdZbxbDwYxjm4Gb24pFTnMp"
    AUTH_SERVER_URL = f"https://auth.{DEFAULT_DOMAIN}"
    SAFETY_PLATFORM_URL = f"https://platform.{DEFAULT_DOMAIN}"
    FIREWALL_API_BASE_URL = "https://pkgs.safetycli.com"


class FeatureType(Enum):
    """
    Defines server-controlled features for dynamic feature management.

    Each enum value represents a toggleable feature controlled through
    server-side configuration, enabling gradual rollouts to different user
    segments. Features are cached during CLI initialization.

    History:
        Created to support progressive feature rollouts and A/B testing without
        disturbing users.
    """

    FIREWALL = "firewall"
    PLATFORM = "platform"
    EVENTS = "events"

    @property
    def config_key(self) -> str:
        """For JSON/config lookup e.g. 'feature-a-enabled'"""
        return f"{self.name.lower()}-enabled"

    @property
    def attr_name(self) -> str:
        """For Python attribute access e.g. 'feature_a_enabled'"""
        return f"{self.name.lower()}_enabled"


def get_config_setting(name: str, default=None) -> Optional[str]:
    """
    Get the configuration setting from the config file or defaults.

    Args:
        name (str): The name of the setting to retrieve.

    Returns:
        Optional[str]: The value of the setting if found, otherwise None.
    """
    config = configparser.ConfigParser()
    config.read(CONFIG)

    if name in [setting.name for setting in URLSettings]:
        default = URLSettings[name]

    if "settings" in config.sections() and name in config["settings"]:
        value = config["settings"][name]
        if value:
            return value

    return default.value if default else default


DATA_API_BASE_URL = get_config_setting("DATA_API_BASE_URL")
PLATFORM_API_BASE_URL = get_config_setting("PLATFORM_API_BASE_URL")

PLATFORM_API_PROJECT_ENDPOINT = f"{PLATFORM_API_BASE_URL}/project"
PLATFORM_API_PROJECT_CHECK_ENDPOINT = f"{PLATFORM_API_BASE_URL}/project-check"
PLATFORM_API_POLICY_ENDPOINT = f"{PLATFORM_API_BASE_URL}/policy"
PLATFORM_API_PROJECT_SCAN_REQUEST_ENDPOINT = (
    f"{PLATFORM_API_BASE_URL}/project-scan-request"
)
PLATFORM_API_PROJECT_UPLOAD_SCAN_ENDPOINT = f"{PLATFORM_API_BASE_URL}/scan"
PLATFORM_API_REQUIREMENTS_UPLOAD_SCAN_ENDPOINT = (
    f"{PLATFORM_API_BASE_URL}/process_files"
)
PLATFORM_API_CHECK_UPDATES_ENDPOINT = f"{PLATFORM_API_BASE_URL}/versions-and-configs"
PLATFORM_API_INITIALIZE_ENDPOINT = f"{PLATFORM_API_BASE_URL}/initialize"
PLATFORM_API_EVENTS_ENDPOINT = f"{PLATFORM_API_BASE_URL}/events"

FIREWALL_API_BASE_URL = get_config_setting("FIREWALL_API_BASE_URL")
FIREWALL_AUDIT_PYPI_PACKAGES_ENDPOINT = f"{FIREWALL_API_BASE_URL}/audit/pypi/packages/"


API_MIRRORS = [DATA_API_BASE_URL]

# Fetch the REQUEST_TIMEOUT from the environment variable, defaulting to 30 if not set
REQUEST_TIMEOUT = int(os.getenv("SAFETY_REQUEST_TIMEOUT", 30))

# Colors
YELLOW = "yellow"
RED = "red"
GREEN = "green"

# MESSAGES
IGNORE_UNPINNED_REQ_REASON = (
    "This vulnerability is being ignored due to the 'ignore-unpinned-requirements' flag (default True). "
    "To change this, set 'ignore-unpinned-requirements' to False under 'security' in your policy file. "
    "See https://docs.pyup.io/docs/safety-20-policy-file for more information."
)

# REGEXES
HASH_REGEX_GROUPS = r"--hash[=| ](\w+):(\w+)"

DOCS_API_KEY_URL = "https://docs.safetycli.com/cli/api-keys"
MSG_NO_AUTHD_DEV_STG = "Please login or register Safety CLI [bold](free forever)[/bold] to scan and secure your projects with Safety"
MSG_NO_AUTHD_DEV_STG_PROMPT = "(R)egister for a free account in 30 seconds, or (L)ogin with an existing account to continue (R/L)"
MSG_NO_AUTHD_DEV_STG_ORG_PROMPT = "Please log in to secure your projects with Safety. Press enter to continue to log in (Y/N)"
MSG_NO_AUTHD_CICD_PROD_STG = "Enter your Safety API key to scan projects in CI/CD using the --key argument or setting your API key in the SAFETY_API_KEY environment variable."
MSG_NO_AUTHD_CICD_PROD_STG_ORG = f"""
Login to get your API key

To log in: [link]{{LOGIN_URL}}[/link]

Read more at: [link]{DOCS_API_KEY_URL}[/link]
"""

MSG_NO_AUTHD_NOTE_CICD_PROD_STG_TPL = f"""
Login or register for a free account to get your API key

To log in: [link]{{LOGIN_URL}}[/link]
To register: [link]{{SIGNUP_URL}}[/link]

Read more at: [link]{DOCS_API_KEY_URL}[/link]
"""

MSG_FINISH_REGISTRATION_TPL = (
    "To complete your account open the “verify your email” email sent to {email}"
)

MSG_VERIFICATION_HINT = "Can’t find the verification email? Login at [link]`https://platform.safetycli.com/login/`[/link] to resend the verification email"

MSG_NO_VERIFIED_EMAIL_TPL = f"""Email verification is required for {{email}}

  {MSG_FINISH_REGISTRATION_TPL}

  {MSG_VERIFICATION_HINT}"""

# Exit codes
EXIT_CODE_OK = 0
EXIT_CODE_FAILURE = 1
EXIT_CODE_VULNERABILITIES_FOUND = 64
EXIT_CODE_INVALID_AUTH_CREDENTIAL = 65
EXIT_CODE_TOO_MANY_REQUESTS = 66
EXIT_CODE_UNABLE_TO_LOAD_LOCAL_VULNERABILITY_DB = 67
EXIT_CODE_UNABLE_TO_FETCH_VULNERABILITY_DB = 68
EXIT_CODE_MALFORMED_DB = 69
EXIT_CODE_INVALID_PROVIDED_REPORT = 70
EXIT_CODE_INVALID_REQUIREMENT = 71
EXIT_CODE_EMAIL_NOT_VERIFIED = 72

# For Depreciated Messages
BAR_LINE = "+===========================================================================================================================================================================================+"

BETA_PANEL_DESCRIPTION_HELP = "These commands are experimental and part of our commitment to delivering innovative features. As we refine functionality, they may be significantly altered or, in rare cases, removed without prior notice. We welcome your feedback and encourage cautious use."

CONTEXT_COMMAND_TYPE = "command_type"
CONTEXT_FEATURE_TYPE = "feature_type"

CLI_VERSION = get_version()
CLI_WEBSITE_URL = "https://safetycli.com"
CLI_DOCUMENTATION_URL = "https://docs.safetycli.com"
CLI_SUPPORT_EMAIL = "support@safetycli.com"

# Main Safety --help data:
CLI_MAIN_INTRODUCTION = (
    f"Safety CLI 3 - Vulnerability Scanning for Secure Python Development\n\n"
    "Leverage the most comprehensive vulnerability data available to secure your projects against vulnerable and malicious packages. Safety CLI is a Python dependency vulnerability scanner that enhances software supply chain security at every stage of development.\n\n"
    f"Documentation: {CLI_DOCUMENTATION_URL}\n"
    f"Contact: {CLI_SUPPORT_EMAIL}\n"
)

DEFAULT_EPILOG = (
    f"\nSafety CLI version: {CLI_VERSION}\n"
    f"\nDocumentation: {CLI_DOCUMENTATION_URL}\n\n\n\n"
    "Made with love by Safety Cybersecurity\n\n"
    f"{CLI_WEBSITE_URL}\n\n"
    f"{CLI_SUPPORT_EMAIL}\n"
)
