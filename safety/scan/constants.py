from safety.util import get_safety_version

# Console Help Theme
CONSOLE_HELP_THEME = {
    "nhc": "grey82"
}

CLI_VERSION = get_safety_version()
CLI_WEBSITE_URL="https://safetycli.com"
CLI_DOCUMENTATION_URL="https://docs.safetycli.com"
CLI_SUPPORT_EMAIL="support@safetycli.com"

# Main Safety --help data:
CLI_MAIN_INTRODUCTION = f"[bold]Safety CLI 3 - Vulnerability Scanning for Secure Python Development[/bold]\n\n" \
"Leverage the most comprehensive vulnerability data available to secure your projects against vulnerable and malicious packages. Safety CLI is a Python dependency vulnerability scanner that enhances software supply chain security at every stage of development.\n\n" \
f"Documentation: [underline]{CLI_DOCUMENTATION_URL}[/underline]\n"\
f"Contact: {CLI_SUPPORT_EMAIL}\n\n"

CLI_AUTH_COMMAND_HELP = "Authenticate Safety CLI to perform scans. Your default browser will automatically open to https://platform.safetycli.com."\
"\n[bold]Example: safety auth login[/bold]"
CLI_SCAN_COMMAND_HELP = "Scans a Python project directory."\
"\n[bold]Example: safety scan[/bold] to scan the current directory"
CLI_SYSTEM_SCAN_COMMAND_HELP = "\\[beta] Run a comprehensive scan for packages and vulnerabilities across your entire machine/environment."\
"\n[bold]Example: safety system-scan[/bold]"

CLI_CHECK_COMMAND_HELP = "\\[deprecated] Find vulnerabilities at target files or enviroments. Now replaced by [bold]safety scan[/bold], and will be unsupported beyond 1 May 2024." \
"\n[bold]Example: safety check -r requirements.txt[/bold]"
CLI_LICENSES_COMMAND_HELP = "\\[deprecated] Find licenses at target files or enviroments. This command will be replaced by [bold]safety scan[/bold], and will be unsupported beyond 1 May 2024." \
"\n[bold]Example: safety license -r requirements.txt[/bold]"


CLI_ALERT_COMMAND_HELP = "\\[deprecated] Create GitHub pull requests or GitHub issues using a `safety check` json report file. Being replaced by newer features." \
"\n[bold]Example: safety alert --check-report your-report.json --key API_KEY github-pr --repo my-org/my-repo --token github-token[/bold]"

CLI_CHECK_UPDATES_HELP = "Check for version updates to Safety CLI."\
"\n[bold]Example: safety check-updates[/bold]"

CLI_CONFIGURE_HELP = "Set up global configurations for Safety CLI, including proxy settings and organization details."\
"\n[bold]Example: safety configure --proxy-host 192.168.0.1[/bold]"

CLI_GENERATE_HELP = "Generate a boilerplate Safety CLI policy file for customized security policies."\
"\nNote: Safety Platform policies will override any local policy files found"\
"\n[bold]Example: safety generate policy_file[/bold]"

CLI_VALIDATE_HELP = "Check if your local Safety CLI policy file is valid."\
"\n[bold]Example: Example: safety validate --path /path/to/policy.yml[/bold]"

# Global options help
_CLI_PROXY_TIP_HELP = f"[nhc]Note: proxy details can be set globally in a config file.[/nhc]\n\nSee [bold]safety configure --help[/bold]\n\n"

CLI_PROXY_HOST_HELP = "Specify a proxy host for network communications. \n\n" + \
 _CLI_PROXY_TIP_HELP

CLI_PROXY_PORT_HELP = "Set the proxy port (default: 80).\n\n" + \
_CLI_PROXY_TIP_HELP

CLI_PROXY_PROTOCOL_HELP = "Choose the proxy protocol (default: https).\n\n" + \
_CLI_PROXY_TIP_HELP

CLI_KEY_HELP = "The API key required for cicd stage or production stage scans.\n\n" \
"[nhc]For development stage scans unset the API key and authenticate using [bold]safety auth[/bold].[/nhc]\n\n" \
"[nhc]Tip: the API key can also be set using the environment variable: SAFETY_API_KEY[/nhc]\n\n"\
"[bold]Example: safety --key API_KEY --stage cicd scan[/bold]"

CLI_STAGE_HELP = "Assign a development lifecycle stage to your scan (default: development).\n\n" \
"[nhc]This labels the scan and its findings in Safety Platform with this stage.[/nhc]\n\n" \
"[bold]Example: safety --stage production scan[/bold]"

CLI_DEBUG_HELP = "Enable debug mode for detailed output.\n\n" \
"[bold]Example: safety --debug scan[/bold]"

CLI_DISABLE_OPTIONAL_TELEMETRY_DATA_HELP = "Opt-out of sending optional telemetry data. Anonymized telemetry data will remain.\n\n" \
"[bold]Example: safety --disable-optional-telemetry scan[/bold]"


# Scan Help options
SCAN_POLICY_FILE_HELP = "Use a local policy file to configure the scan.\n\n" \
    "[nhc]Note: Project scan policies defined in Safety Platform will override local policy files[/nhc]\n\n" \
    "[bold]Example: safety scan --policy-file /path/to/policy.yml[/bold]"
SCAN_TARGET_HELP = "Define a specific project path to scan. (default: current directory)\n\n" \
    "[bold]Example: safety scan --target /path/to/project[/bold]"
SCAN_OUTPUT_HELP = "Set the output format for scan results (default: screen)\n\n" \
    "[bold]Example: safety scan --output json[/bold]"
SCAN_SAVE_AS_HELP = "In addition to regular output save the scan results to a json, html, text, or spdx file using: FORMAT FILE_PATH\n\n" \
    "[bold]Example: safety scan --save-as json results.json[/bold]"
SCAN_DETAILED_OUTPUT = "Enable a verbose scan report for detailed insights (only for screen output)\n\n" \
    "[bold]Example: safety scan --detailed-output[/bold]"
SCAN_APPLY_FIXES = "[bold]Update packages listed in requirements.txt files to secure versions where possible[/bold]\n\n"\
    "[nhc]Currently supports: requirements.txt files[/nhc]\n\n"\
    "Note: this will update your requirements.txt file "

# System Scan options
SYSTEM_SCAN_POLICY_FILE_HELP = "Use a local policy file to configure the scan.\n\n" \
    "[nhc]Note: Scan policies defined in Safety Platform will override local policy files[/nhc]\n\n" \
    "[bold]Example: safety scan --policy-file /path/to/policy.yml[/bold]"
SYSTEM_SCAN_TARGET_HELP = "Define a specific location to start the system scan. (default: current directory)\n\n" \
    "[bold]Example: safety scan --target /path/to/project[/bold]"
SYSTEM_SCAN_OUTPUT_HELP = "Set the output format for scan results (default: screen)\n\n" \
    "[bold]Example: safety scan --output json[/bold]"
SYSTEM_SCAN_SAVE_AS_HELP = "In addition to the terminal/console output (set by --output), save system-scan results to a screen (text) or json file.\n\n" \
    """[nhc]Use [bold]--save-as <FORMAT> <PATH>[/bold]. For example: [bold]--save-as json my-machine-scan.json[/bold] to save the system-scan results to `my-machine-scan.json` in the current directory[/nhc]\n\n""" \
    "[nhc][Default: json .][/nhc]"

# Auth options
CLI_AUTH_LOGIN_HELP = "Authenticate with Safety CLI to perform scans. Your default browser will automatically open to https://platform.safetycli.com unless already authenticated.\n\n" \
    "[bold]Example: safety auth login[/bold]"
CLI_AUTH_LOGOUT_HELP = "Log out from the current Safety CLI session.\n\n" \
    "[bold]Example: safety auth logout[/bold]"
CLI_AUTH_STATUS_HELP = "Show the current authentication status.\n\n" \
    "[bold]Example: safety auth status[/bold]"

DEFAULT_EPILOG = f"\nSafety CLI version: {CLI_VERSION}\n" \
    f"\nDocumentation: [underline]{CLI_DOCUMENTATION_URL}[/underline]\n\n\n\n" \
    "Made with :heart: by [purple]Safety Cybersecurity[/purple]\n\n" \
    f"{CLI_WEBSITE_URL}\n\n"\
    f"{CLI_SUPPORT_EMAIL}\n\n"

# Configure options
CLI_CONFIGURE_PROXY_HOST_HELP = "Specify a proxy host for network communications to be saved into Safety's configuration. \n\n"
CLI_CONFIGURE_PROXY_PORT_HELP = "Set the proxy port to be saved into Safety's configuration file (default: 80).\n\n"
CLI_CONFIGURE_PROXY_PROTOCOL_HELP = "Choose the proxy protocol to be saved into Safety's configuration file (default: https).\n\n"
CLI_CONFIGURE_PROXY_TIMEOUT = "Set the timeout duration for proxy network calls.\n\n" + \
"[bold]Example: safety configure --proxy-timeout 30[/bold]"
CLI_CONFIGURE_PROXY_REQUIRED = "Enable or disable the requirement for a proxy in network communications\n\n" + \
"[bold]Example: safety configure --proxy-required[/bold]"
CLI_CONFIGURE_ORGANIZATION_ID = "Set the current device with an organization ID." \
" - see your Safety Platform Organization page\n\n" + \
"[bold]Example: safety configure --organization-id your_org_unique_id[/bold]"
CLI_CONFIGURE_ORGANIZATION_NAME = "Set the current device with an organization name." \
" - see your Safety Platform Organization page.\n\n" + \
"[bold]Example: safety configure --organization-name \"Your Org Name\"[/bold]"
CLI_CONFIGURE_SAVE_TO_SYSTEM = "Save the configuration to a system config file.\n" \
"This will configure Safety CLI for all users on this machine. Use --save-to-user to " \
"configure Safety CLI for only your user.\n\n" \
"[bold]Example: safety configure --save-to-system[/bold]"

# Generate options
CLI_GENERATE_PATH = "The path where the generated file will be saved (default: current directory).\n\n" \
"[bold]Example: safety generate policy_file --path .my-project-safety-policy.yml[/bold]"

# Command default settings
CMD_PROJECT_NAME = "scan"
CMD_SYSTEM_NAME = "system-scan"
DEFAULT_CMD = CMD_PROJECT_NAME
DEFAULT_SPINNER = "bouncingBar" 