from safety.constants import get_required_config_setting

HOST: str = "localhost"

CLIENT_ID = get_required_config_setting("CLIENT_ID")
AUTH_SERVER_URL = get_required_config_setting("AUTH_SERVER_URL")
SAFETY_PLATFORM_URL = get_required_config_setting("SAFETY_PLATFORM_URL")
OAUTH2_SCOPE = "openid email profile offline_access"


OPENID_CONFIG_URL = f"{AUTH_SERVER_URL}/.well-known/openid-configuration"

CLAIM_EMAIL_VERIFIED_API = "https://api.safetycli.com/email_verified"
CLAIM_EMAIL_VERIFIED_AUTH_SERVER = "email_verified"

CLI_AUTH = f"{SAFETY_PLATFORM_URL}/cli/auth"
CLI_AUTH_SUCCESS = f"{SAFETY_PLATFORM_URL}/cli/auth/success"
CLI_AUTH_LOGOUT = f"{SAFETY_PLATFORM_URL}/cli/logout"
CLI_CALLBACK = f"{SAFETY_PLATFORM_URL}/cli/callback"
CLI_LOGOUT_SUCCESS = f"{SAFETY_PLATFORM_URL}/cli/logout/success"

MSG_NON_AUTHENTICATED = (
    "Safety is not authenticated. Please run 'safety auth login' to log in"
    " or 'safety auth enroll' to enroll via MDM."
)
MSG_FAIL_LOGIN_AUTHED = """[green]You are authenticated as[/green] {email}.

To log into a different account, first logout via: safety auth logout, and then login again."""
MSG_FAIL_REGISTER_AUTHED = "You are currently logged in to {email}, please logout using `safety auth logout` before registering a new account."

MSG_LOGOUT_DONE = "[green]Logout done.[/green]"
MSG_LOGOUT_FAILED = "[red]Logout failed. Try again.[/red]"

ENROLLMENT_ENDPOINT = "/api/enroll"
ENROLLMENT_KEY_PATTERN = r"^sfek_[A-Za-z0-9_-]{43}$"
MACHINE_ID_MAX_LENGTH = 255
MSG_MACHINE_TOKEN_NOT_ACCEPTED = "Machine token authentication is not accepted for this operation. Run 'safety auth login' or use '--key' to authenticate."
