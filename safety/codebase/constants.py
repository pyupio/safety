CMD_HELP_CODEBASE_INIT = "Initialize a Safety Codebase (like git init for security). Sets up a new codebase or connects your local project to an existing one on Safety Platform."
CMD_HELP_CODEBASE = (
    "[BETA] Manage your Safety Codebase integration.\nExample: safety codebase init"
)

CMD_CODEBASE_GROUP_NAME = "codebase"
CMD_CODEBASE_INIT_NAME = "init"


# init options help
CMD_HELP_CODEBASE_INIT_NAME = "Name of the codebase. Defaults to GIT origin name, parent directory name, or random string if parent directory is unnamed. The value will be normalized for use as an identifier."
CMD_HELP_CODEBASE_INIT_LINK_TO = (
    "Link to an existing codebase using its codebase slug (found in Safety Platform)."
)
CMD_HELP_CODEBASE_INIT_DISABLE_FIREWALL = "Don't enable Firewall protection for this codebase (enabled by default when available in your organization)"
CMD_HELP_CODEBASE_INIT_PATH = (
    "Path to the codebase directory. Defaults to current directory."
)


CODEBASE_INIT_REINITIALIZED = "Reinitialized existing codebase {codebase_name}"
CODEBASE_INIT_ALREADY_EXISTS = "A codebase already exists in this directory. Please delete .safety-project.ini and run `safety codebase init` again to initialize a new codebase."
CODEBASE_INIT_NOT_FOUND_LINK_TO = "\nError: codebase '{codebase_name}' specified with --link-to does not exist.\n\nTo create a new codebase instead, use one of:\n  safety codebase init\n  safety codebase init --name \"custom name\"\n\nTo link to an existing codebase, verify the codebase id and try again."
CODEBASE_INIT_NOT_FOUND_PROJECT_FILE = "\nError: codebase '{codebase_name}' specified with the current .safety-project.ini file does not exist.\n\nTo create a new codebase instead, delete the corrupted .safety-project.ini file and then use one of:\n  safety codebase init\n  safety codebase init --name \"custom name\"\n\nTo link to an existing codebase, verify the codebase id and try again."
CODEBASE_INIT_LINKED = "Linked to codebase {codebase_name}."
CODEBASE_INIT_CREATED = "Created new codebase {codebase_name}."
CODEBASE_INIT_ERROR = "Error: unable to initialize the codebase. Please try again."
