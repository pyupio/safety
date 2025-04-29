# Codebase options
import sys


CODEBASE_INIT_CMD_NAME = "init"
CODEBASE_INIT_HELP = (
    "[BETA] Used to install Safety Firewall globally, or to initialize a codebase in the current directory."
    "\nExample: safety init"
)
CODEBASE_INIT_DIRECTORY_HELP = (
    "[BETA] Defines a directory for creating a codebase. (default: current directory)\n\n"
    "[bold]Example: safety init /path/to/codebase[/bold]"
)

# Welcome Section
MSG_WELCOME_TITLE = (
    "\n\nWelcome to Safety, the AI-powered Software Supply Chain Firewall.\n\n"
)
MSG_WELCOME_DESCRIPTION = (
    "[bold]Safety is designed to:[/bold]",
    "1. Work with your existing package manager to block malicious or high-risk packages before they're installed.",
    "2. Keep track of the dependencies in your codebase, and help you to quickly fix any vulnerabilities in them.",
    "3. Integrate with your AI assistants to ensure they use secure packages.\n",
)

MSG_NEED_AUTHENTICATION = "To configure firewall and your codebase security settings, you'll need an account.\n"
MSG_AUTH_PROMPT = (
    "Press [bold]R[/bold] to register (it's free & quick), or [bold]L[/bold] to log in"
)

MSG_SETUP_PACKAGE_FIREWALL_TITLE = "  Set Up Package Firewall"

MSG_SETUP_PACKAGE_FIREWALL_DESCRIPTION = "Let's configure Safety Firewall to protect your package installations. This won't change the way you use pip and you'll only notice it when it blocks a malicious or vulnerable package. You can uninstall Firewall at any time with:\n"
MSG_FIREWALL_UNINSTALL = "`safety firewall uninstall`\n"

ASK_HINT = "[Press Enter to continue, n to cancel]"

MSG_SETUP_PACKAGE_FIREWALL_PROMPT = (
    f"[bold]Do you want to continue with Firewall installation? {ASK_HINT}[/bold]"
)

SUPPORT_DETAILS = (
    "[link]support@safetycli.com[/link] (we normally respond within 4 hours)"
)

MSG_SETUP_INCOMPLETE = f"[red bold]x[/red bold] The setup was not completed successfully, reach out to {SUPPORT_DETAILS}"

MSG_SETUP_PACKAGE_FIREWALL_RESULT = "configured and secured. Safety will analyze package installations for security risks before installation, and warn you if you install vulnerable packages.\n"
MSG_SETUP_PACKAGE_FIREWALL_NOTE_STATUS = "To see your firewall status, usage and to configure your firewall security settings visit [link]https://platform.safetycli.com/firewall/[/link]"

MSG_SETUP_CONTINUE_PROMPT = "[bold][Press Enter to continue][/bold]"

MSG_SETUP_CODEBASE_TITLE = " Secure Your First Codebase"

MSG_SETUP_CODEBASE_DESCRIPTION = "Safety monitors your codebase for open source dependency vulnerabilities and risk, surfacing reachable vulnerabilities that pose actual risk, and gives you advice on what to fix and how.\n"

MSG_SETUP_CODEBASE_PROMPT = (
    f"[bold]Would you like to secure this codebase with Safety? {ASK_HINT}[/bold]"
)

MSG_SETUP_CODEBASE_NO_PROJECT = "We didn't find any dependency specification files in the current directory. Please navigate to a Python codebase directory and run:\n\n`safety init`"

MSG_ANALYZE_CODEBASE_TITLE = " Analyze {project_name} for Vulnerabilities"

MSG_NO_VULNERABILITIES_FOUND = "  No vulnerabilities found 🎉\n\n"
MSG_CODEBASE_URL_DESCRIPTION = "🔎 View detailed results in your Safety dashboard:\n"
MSG_NO_VULNS_CODEBASE_URL_DESCRIPTION = (
    "🔎 Any future vulnerabilities will appear here:\n"
)

MSG_OPEN_DASHBOARD_PROMPT = f"💡 Open this in a new browser window now? {ASK_HINT}"

MSG_COMMAND_TO_RUN = "`source ~/.safety/.safety_profile`"
MSG_LAST_MANUAL_STEP = (
    "🟡 IMPORTANT: At the end, restart the terminal to activate your Safety configuration."
    if sys.platform == "win32"
    else f"🟡 IMPORTANT: Run {MSG_COMMAND_TO_RUN} to activate your Safety configuration."
)

MSG_SETUP_COMPLETE_TITLE = " Wrap Up"

MSG_SETUP_COMPLETE_SUBTITLE = "Almost done! Final step:"

MSG_TOOLS_NOT_CONFIGURED = "[bold red]x[/bold red] No package managers configured"
MSG_CODEBASE_NOT_CONFIGURED = "[bold red]x[/bold red] No codebase configured"
MSG_CODEBASE_FAILED_TO_SCAN = (
    "[bold red]x[/bold red] Failed to complete the codebase scan, reason: {reason}. Reach out to "
    + SUPPORT_DETAILS
)
MSG_COMPLETE_TOOL_SECURED = "✅ {tools} secured - Safety is automatically analyzing all package installations for risk. To configure or audit your installations visit [link]{firewall_url}[/link]"
MSG_COMPLETE_SECURED = "✅ Codebase secured - to see your vulnerable packages, visit [link]{codebase_url}[/link]"

MSG_SETUP_NEXT_STEPS_SUBTITLE = " Next steps:"

MSG_HELP = f"💬 Need help or want to give feedback? {SUPPORT_DETAILS}"
MSG_DOCS = "📚 Read the docs: [link]https://docs.safetycli.com[/link]"
MSG_TEAM = (
    "👥 Invite your team: [link]https://platform.safetycli.com/organization/team[/link]"
)


MSG_SETUP_NEXT_STEPS = (
    MSG_TEAM,
    "💾 Commit `.safety-project.ini` to your Github repository so that your team-members use the same codebase.",
    "➕ Add another codebase: `safety init` (run this in the codebase directory)",
    MSG_DOCS,
    MSG_HELP,
)

MSG_SETUP_NEXT_STEPS_ERROR = (MSG_HELP, MSG_DOCS)

MSG_SETUP_NEXT_STEPS_NO_PROJECT = (
    "➕ Add a codebase with `safety init` (run this in the codebase directory)",
    MSG_TEAM,
    MSG_DOCS,
    MSG_HELP,
)

MSG_SETUP_NEXT_STEPS_NO_VULNS = (MSG_TEAM, MSG_DOCS, MSG_HELP)

MSG_SETUP_NEXT_STEPS_MANUAL_STEP = (
    "(Don't forget to restart the terminal now!)"
    if sys.platform == "win32"
    else f"(Don't forget to run {MSG_COMMAND_TO_RUN} now!)"
)
