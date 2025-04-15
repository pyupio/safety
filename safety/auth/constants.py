from pathlib import Path

from safety.constants import USER_CONFIG_DIR, get_config_setting

AUTH_CONFIG_FILE_NAME = "auth.ini"
AUTH_CONFIG_USER = USER_CONFIG_DIR / Path(AUTH_CONFIG_FILE_NAME)


HOST: str = "localhost"

CLIENT_ID = get_config_setting("CLIENT_ID")
AUTH_SERVER_URL = get_config_setting("AUTH_SERVER_URL")
SAFETY_PLATFORM_URL = get_config_setting("SAFETY_PLATFORM_URL")

OPENID_CONFIG_URL = f"{AUTH_SERVER_URL}/.well-known/openid-configuration"

CLAIM_EMAIL_VERIFIED_API = "https://api.safetycli.com/email_verified"
CLAIM_EMAIL_VERIFIED_AUTH_SERVER = "email_verified"

CLI_AUTH = f"{SAFETY_PLATFORM_URL}/cli/auth"
CLI_AUTH_SUCCESS = f"{SAFETY_PLATFORM_URL}/cli/auth/success"
CLI_AUTH_LOGOUT = f"{SAFETY_PLATFORM_URL}/cli/logout"
CLI_CALLBACK = f"{SAFETY_PLATFORM_URL}/cli/callback"
CLI_LOGOUT_SUCCESS = f"{SAFETY_PLATFORM_URL}/cli/logout/success"

MSG_NON_AUTHENTICATED = (
    "Safety is not authenticated. Please run 'safety auth login' to log in."
)
MSG_FAIL_LOGIN_AUTHED = """[green]You are authenticated as[/green] {email}.

To log into a different account, first logout via: safety auth logout, and then login again."""
MSG_FAIL_REGISTER_AUTHED = "You are currently logged in to {email}, please logout using `safety auth logout` before registering a new account."

MSG_LOGOUT_DONE = "[green]Logout done.[/green]"
MSG_LOGOUT_FAILED = "[red]Logout failed. Try again.[/red]"
