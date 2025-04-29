MSG_UNINSTALL_EXPLANATION = "Would you like to uninstall Safety Firewall on this machine? Doing so will mean you are no longer protected from malicious or vulnerable packages."
MSG_UNINSTALL_SUCCESS = "Safety Firewall has been uninstalled from your machine. Note that your individual requirements files may still reference Safety Firewall. You can remove these references by removing the following line from your requirements files:"
MSG_REQ_FILE_LINE = "-i https://pkgs.safetycli.com/repository/public/pypi/simple/"

MSG_FEEDBACK = "We're sorry to see you go. If you have any feedback on how we can do better, we'd love to hear it. Otherwise hit enter to exit."


UNINSTALL_HELP = "Uninstall Safety Firewall from your machine."


FIREWALL_CMD_NAME = "firewall"
UNINSTALL_CMD_NAME = "uninstall"


FIREWALL_HELP = "[BETA] Manage Safety Firewall settings."

MSG_UNINSTALL_CONFIG = (
    "Removing global configuration for pip from: ~/.config/pip/pip.conf",
    "Removing global configuration for uv from: uv.toml",
)
MSG_UNINSTALL_WRAPPERS = "Removing aliases to safety from config files"
