import logging
import subprocess
import sys
from collections import defaultdict
from enum import Enum
from functools import wraps

import time
from typing import (
    TYPE_CHECKING,
    Any,
    DefaultDict,
    Dict,
    List,
    Optional,
    Tuple,
    Union,
    cast,
)

import click
import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from typer.core import MarkupMode, TyperCommand, TyperGroup
from click.utils import make_str


from safety.constants import (
    BETA_PANEL_DESCRIPTION_HELP,
    MSG_NO_AUTHD_CICD_PROD_STG,
    MSG_NO_AUTHD_CICD_PROD_STG_ORG,
    MSG_NO_AUTHD_DEV_STG,
    MSG_NO_AUTHD_DEV_STG_ORG_PROMPT,
    MSG_NO_AUTHD_DEV_STG_PROMPT,
    MSG_NO_AUTHD_NOTE_CICD_PROD_STG_TPL,
    MSG_NO_VERIFIED_EMAIL_TPL,
    CONTEXT_COMMAND_TYPE,
    FeatureType,
)
from safety.scan.constants import CONSOLE_HELP_THEME
from safety.models import SafetyCLI

if TYPE_CHECKING:
    from click.core import Command, Context
    from safety.auth.models import Auth


LOG = logging.getLogger(__name__)


class CommandType(Enum):
    MAIN = "main"
    UTILITY = "utility"
    BETA = "beta"


def custom_print_options_panel(
    name: str, params: List[Any], ctx: Any, console: Console
) -> None:
    """
    Print a panel with options.

    Args:
        name (str): The title of the panel.
        params (List[Any]): The list of options/arguments to print.
        ctx (Any): The context object.
        markup_mode (str): The markup mode.
        console (Console): The console to print to.
    """
    table = Table(title=name, show_lines=True)
    for param in params:
        opts = getattr(param, "opts", "")
        help_text = getattr(param, "help", "")
        table.add_row(str(opts), help_text)
    console.print(table)


def custom_print_commands_panel(
    name: str, commands: List[Any], console: Console
) -> None:
    """
    Print a panel with commands.

    Args:
        name (str): The title of the panel.
        commands (List[Any]): The list of commands to print.
        console (Console): The console to print to.
    """
    table = Table(title=name, show_lines=True)
    for command in commands:
        table.add_row(command.name, command.help or "")
    console.print(table)


def custom_make_rich_text(text: str) -> Text:
    """
    Create rich text.

    Args:
        text (str): The text to format.

    Returns:
        Text: The formatted rich text.
    """
    return Text(text)


def custom_get_help_text(obj: Any) -> Text:
    """
    Get the help text for an object.

    Args:
        obj (Any): The object to get help text for.

    Returns:
        Text: The formatted help text.
    """
    return Text(obj.help)


def custom_make_command_help(help_text: str) -> Text:
    """
    Create rich text for command help.

    Args:
        help_text (str): The help text to format.
        markup_mode (str): The markup mode.

    Returns:
        Text: The formatted rich text.
    """
    return Text(help_text)


def get_command_for(name: str, typer_instance: typer.Typer) -> click.Command:
    """
    Retrieve a command by name from a Typer instance.

    Args:
        name (str): The name of the command.
        typer_instance (typer.Typer): The Typer instance.

    Returns:
        click.Command: The found command.
    """
    single_command = next(
        (
            command
            for command in typer_instance.registered_commands
            if command.name == name
        ),
        None,
    )

    if not single_command:
        raise ValueError("Unable to find the command name.")

    single_command.context_settings = typer_instance.info.context_settings
    click_command = typer.main.get_command_from_info(
        single_command,
        pretty_exceptions_short=typer_instance.pretty_exceptions_short,
        rich_markup_mode=typer_instance.rich_markup_mode,
    )
    if typer_instance._add_completion:
        click_install_param, click_show_param = (
            typer.main.get_install_completion_arguments()
        )
        click_command.params.append(click_install_param)
        click_command.params.append(click_show_param)
    return click_command


def pass_safety_cli_obj(func):
    """
    Decorator to ensure the SafetyCLI object exists for a command.
    """

    @wraps(func)
    def inner(ctx, *args, **kwargs):
        if not ctx.obj:
            ctx.obj = SafetyCLI()

        return func(ctx, *args, **kwargs)

    return inner


def pretty_format_help(
    obj: Union[click.Command, click.Group], ctx: click.Context, markup_mode: MarkupMode
) -> None:
    """
    Format and print help text in a pretty format.

    Args:
        obj (Union[click.Command, click.Group]): The Click command or group.
        ctx (click.Context): The Click context.
        markup_mode (MarkupMode): The markup mode.
    """
    from rich.align import Align
    from rich.console import Console
    from rich.padding import Padding
    from rich.theme import Theme
    from typer.rich_utils import (
        ARGUMENTS_PANEL_TITLE,
        COMMANDS_PANEL_TITLE,
        OPTIONS_PANEL_TITLE,
        STYLE_USAGE_COMMAND,
        highlighter,
    )

    console = Console()

    with console.use_theme(Theme(styles=CONSOLE_HELP_THEME)) as theme_context:
        console = theme_context.console
        # Print command / group help if we have some
        if obj.help:
            console.print()

            # Print with some padding
            console.print(
                Padding(Align(custom_get_help_text(obj=obj), pad=False), (0, 1, 0, 1))
            )

        # Print usage
        console.print(
            Padding(highlighter(obj.get_usage(ctx)), 1), style=STYLE_USAGE_COMMAND
        )

        if isinstance(obj, click.MultiCommand):
            panel_to_commands: DefaultDict[str, List[click.Command]] = defaultdict(list)
            for command_name in obj.list_commands(ctx):
                command = obj.get_command(ctx, command_name)
                if command and not command.hidden:
                    panel_name = (
                        getattr(command, "rich_help_panel", None)
                        or COMMANDS_PANEL_TITLE
                    )
                    panel_to_commands[panel_name].append(command)

            # Print each command group panel
            default_commands = panel_to_commands.get(COMMANDS_PANEL_TITLE, [])
            custom_print_commands_panel(
                name=COMMANDS_PANEL_TITLE,
                commands=default_commands,
                console=console,
            )
            for panel_name, commands in panel_to_commands.items():
                if panel_name == COMMANDS_PANEL_TITLE:
                    # Already printed above
                    continue
                custom_print_commands_panel(
                    name=panel_name,
                    commands=commands,
                    console=console,
                )

        panel_to_arguments: DefaultDict[str, List[click.Argument]] = defaultdict(list)
        panel_to_options: DefaultDict[str, List[click.Option]] = defaultdict(list)
        for param in obj.get_params(ctx):
            # Skip if option is hidden
            if getattr(param, "hidden", False):
                continue
            if isinstance(param, click.Argument):
                panel_name = (
                    getattr(param, "rich_help_panel", None) or ARGUMENTS_PANEL_TITLE
                )
                panel_to_arguments[panel_name].append(param)
            elif isinstance(param, click.Option):
                panel_name = (
                    getattr(param, "rich_help_panel", None) or OPTIONS_PANEL_TITLE
                )
                panel_to_options[panel_name].append(param)

        default_options = panel_to_options.get(OPTIONS_PANEL_TITLE, [])
        custom_print_options_panel(
            name=OPTIONS_PANEL_TITLE,
            params=default_options,
            ctx=ctx,
            console=console,
        )
        for panel_name, options in panel_to_options.items():
            if panel_name == OPTIONS_PANEL_TITLE:
                # Already printed above
                continue
            custom_print_options_panel(
                name=panel_name,
                params=options,
                ctx=ctx,
                console=console,
            )

        default_arguments = panel_to_arguments.get(ARGUMENTS_PANEL_TITLE, [])
        custom_print_options_panel(
            name=ARGUMENTS_PANEL_TITLE,
            params=default_arguments,
            ctx=ctx,
            console=console,
        )
        for panel_name, arguments in panel_to_arguments.items():
            if panel_name == ARGUMENTS_PANEL_TITLE:
                # Already printed above
                continue
            custom_print_options_panel(
                name=panel_name,
                params=arguments,
                ctx=ctx,
                console=console,
            )

        if ctx.parent:
            params = []
            for param in ctx.parent.command.params:
                if isinstance(param, click.Option):
                    params.append(param)

            custom_print_options_panel(
                name="Global-Options",
                params=params,
                ctx=ctx.parent,
                console=console,
            )

        # Epilogue if we have it
        if obj.epilog:
            # Remove single linebreaks, replace double with single
            lines = obj.epilog.split("\n\n")
            epilogue = "\n".join([x.replace("\n", " ").strip() for x in lines])
            epilogue_text = custom_make_rich_text(text=epilogue)
            console.print(Padding(Align(epilogue_text, pad=False), 1))


def print_main_command_panels(
    *,
    name: str,
    commands_type: CommandType,
    commands: List[click.Command],
    markup_mode: MarkupMode,
    console,
) -> None:
    """
    Print the main command panels.

    Args:
        name (str): The name of the panel.
        commands (List[click.Command]): List of commands to display.
        markup_mode (MarkupMode): The markup mode.
        console: The Rich console.
    """
    from rich import box
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from typer.rich_utils import (
        ALIGN_COMMANDS_PANEL,
        STYLE_COMMANDS_PANEL_BORDER,
        STYLE_COMMANDS_TABLE_BORDER_STYLE,
        STYLE_COMMANDS_TABLE_BOX,
        STYLE_COMMANDS_TABLE_LEADING,
        STYLE_COMMANDS_TABLE_PAD_EDGE,
        STYLE_COMMANDS_TABLE_PADDING,
        STYLE_COMMANDS_TABLE_ROW_STYLES,
        STYLE_COMMANDS_TABLE_SHOW_LINES,
    )

    t_styles: Dict[str, Any] = {
        "show_lines": STYLE_COMMANDS_TABLE_SHOW_LINES,
        "leading": STYLE_COMMANDS_TABLE_LEADING,
        "box": STYLE_COMMANDS_TABLE_BOX,
        "border_style": STYLE_COMMANDS_TABLE_BORDER_STYLE,
        "row_styles": STYLE_COMMANDS_TABLE_ROW_STYLES,
        "pad_edge": STYLE_COMMANDS_TABLE_PAD_EDGE,
        "padding": STYLE_COMMANDS_TABLE_PADDING,
    }
    box_style = getattr(box, t_styles.pop("box"), None)

    commands_table = Table(
        highlight=False,
        show_header=False,
        expand=True,
        box=box_style,
        **t_styles,
    )

    console_width = 80
    column_width = 25

    if console.size and console.size[0] > 80:
        console_width = console.size[0]

    from rich.console import Group

    description = None

    if commands_type is CommandType.BETA:
        description = Group(Text(""), Text(BETA_PANEL_DESCRIPTION_HELP), Text(""))

    commands_table.add_column(
        style="bold cyan", no_wrap=True, width=column_width, max_width=column_width
    )
    commands_table.add_column(width=console_width - column_width)

    rows = []

    for command in commands:
        helptext = command.short_help or command.help or ""
        command_name = command.name or ""
        command_name_text = (
            Text(command_name, style="")
            if commands_type is CommandType.BETA
            else Text(command_name)
        )
        rows.append(
            [
                command_name_text,
                custom_make_command_help(
                    help_text=helptext,
                ),
            ]
        )
        rows.append([])
    for row in rows:
        commands_table.add_row(*row)
    if commands_table.row_count:
        renderables = (
            [description, commands_table]
            if description is not None
            else [Text(""), commands_table]
        )

        console.print(
            Panel(
                Group(*renderables),
                border_style=STYLE_COMMANDS_PANEL_BORDER,
                title=name,
                title_align=ALIGN_COMMANDS_PANEL,
            )
        )


# The help output for the main safety root command: `safety --help`
def format_main_help(
    obj: Union[click.Command, click.Group], ctx: click.Context, markup_mode: MarkupMode
) -> None:
    """
    Format the main help output for the safety root command.

    Args:
        obj (Union[click.Command, click.Group]): The Click command or group.
        ctx (click.Context): The Click context.
        markup_mode (MarkupMode): The markup mode.
    """
    from rich.align import Align
    from rich.console import Console
    from rich.padding import Padding
    from rich.theme import Theme
    from typer.rich_utils import (
        ARGUMENTS_PANEL_TITLE,
        COMMANDS_PANEL_TITLE,
        OPTIONS_PANEL_TITLE,
        STYLE_USAGE_COMMAND,
        highlighter,
    )

    typer_console = Console()

    with typer_console.use_theme(Theme(styles=CONSOLE_HELP_THEME)) as theme_context:
        console = theme_context.console

        # Print command / group help if we have some
        if obj.help:
            console.print()
            # Print with some padding
            console.print(
                Padding(
                    Align(
                        custom_get_help_text(obj=obj),
                        pad=False,
                    ),
                    (0, 1, 0, 1),
                )
            )

        # Print usage
        console.print(
            Padding(highlighter(obj.get_usage(ctx)), 1), style=STYLE_USAGE_COMMAND
        )

        if isinstance(obj, click.MultiCommand):
            UTILITY_COMMANDS_PANEL_TITLE = "Utility commands"
            BETA_COMMANDS_PANEL_TITLE = "Beta Commands :rocket:"

            COMMANDS_PANEL_TITLE_CONSTANTS = {
                CommandType.MAIN: COMMANDS_PANEL_TITLE,
                CommandType.UTILITY: UTILITY_COMMANDS_PANEL_TITLE,
                CommandType.BETA: BETA_COMMANDS_PANEL_TITLE,
            }

            panel_to_commands: Dict[CommandType, List[click.Command]] = {}

            # Keep order of panels
            for command_type in COMMANDS_PANEL_TITLE_CONSTANTS.keys():
                panel_to_commands[command_type] = []

            for command_name in obj.list_commands(ctx):
                command = obj.get_command(ctx, command_name)
                if command and not command.hidden:
                    command_type = command.context_settings.get(
                        CONTEXT_COMMAND_TYPE, CommandType.MAIN
                    )
                    panel_to_commands[command_type].append(command)

            for command_type, commands in panel_to_commands.items():
                print_main_command_panels(
                    name=COMMANDS_PANEL_TITLE_CONSTANTS[command_type],
                    commands_type=command_type,
                    commands=commands,
                    markup_mode=markup_mode,
                    console=console,
                )

        panel_to_arguments: DefaultDict[str, List[click.Argument]] = defaultdict(list)
        panel_to_options: DefaultDict[str, List[click.Option]] = defaultdict(list)
        for param in obj.get_params(ctx):
            # Skip if option is hidden
            if getattr(param, "hidden", False):
                continue
            if isinstance(param, click.Argument):
                panel_name = (
                    getattr(param, "rich_help_panel", None) or ARGUMENTS_PANEL_TITLE
                )
                panel_to_arguments[panel_name].append(param)
            elif isinstance(param, click.Option):
                panel_name = (
                    getattr(param, "rich_help_panel", None) or OPTIONS_PANEL_TITLE
                )
                panel_to_options[panel_name].append(param)
        default_arguments = panel_to_arguments.get(ARGUMENTS_PANEL_TITLE, [])
        custom_print_options_panel(
            name=ARGUMENTS_PANEL_TITLE,
            params=default_arguments,
            ctx=ctx,
            console=console,
        )
        for panel_name, arguments in panel_to_arguments.items():
            if panel_name == ARGUMENTS_PANEL_TITLE:
                # Already printed above
                continue
            custom_print_options_panel(
                name=panel_name,
                params=arguments,
                ctx=ctx,
                console=console,
            )
        default_options = panel_to_options.get(OPTIONS_PANEL_TITLE, [])
        custom_print_options_panel(
            name=OPTIONS_PANEL_TITLE,
            params=default_options,
            ctx=ctx,
            console=console,
        )
        for panel_name, options in panel_to_options.items():
            if panel_name == OPTIONS_PANEL_TITLE:
                # Already printed above
                continue
            custom_print_options_panel(
                name=panel_name,
                params=options,
                ctx=ctx,
                console=console,
            )

        # Epilogue if we have it
        if obj.epilog:
            # Remove single linebreaks, replace double with single
            lines = obj.epilog.split("\n\n")
            epilogue = "\n".join([x.replace("\n", " ").strip() for x in lines])
            epilogue_text = custom_make_rich_text(text=epilogue)
            console.print(Padding(Align(epilogue_text, pad=False), 1))


def process_auth_status_not_ready(console, auth: "Auth", ctx: typer.Context) -> None:
    """
    Handle the process when the authentication status is not ready.

    Args:
        console: The Rich console.
        auth (Auth): The Auth object.
        ctx (typer.Context): The Typer context.
    """
    from rich.prompt import Confirm, Prompt
    from safety_schemas.models import Stage
    from safety.auth.constants import CLI_AUTH, MSG_NON_AUTHENTICATED

    if not auth.client or not auth.client.is_using_auth_credentials():
        if auth.stage is Stage.development:
            console.print()
            if auth.org:
                confirmed = Confirm.ask(
                    MSG_NO_AUTHD_DEV_STG_ORG_PROMPT,
                    choices=["Y", "N", "y", "n"],
                    show_choices=False,
                    show_default=False,
                    default=True,
                    console=console,
                )

                if not confirmed:
                    sys.exit(0)

                from safety.auth.cli import auth_app

                login_command = get_command_for(name="login", typer_instance=auth_app)
                ctx.invoke(login_command)
            else:
                console.print(MSG_NO_AUTHD_DEV_STG)
                console.print()
                choices = ["L", "R", "l", "r"]
                next_command = Prompt.ask(
                    MSG_NO_AUTHD_DEV_STG_PROMPT,
                    default=None,
                    choices=choices,
                    show_choices=False,
                    console=console,
                )

                from safety.auth.cli import auth_app

                login_command = get_command_for(name="login", typer_instance=auth_app)
                register_command = get_command_for(
                    name="register", typer_instance=auth_app
                )
                if next_command is None or next_command.lower() not in choices:
                    sys.exit(0)

                console.print()
                if next_command.lower() == "r":
                    ctx.invoke(register_command)
                else:
                    ctx.invoke(login_command)

                if not ctx.obj.auth.email_verified:
                    sys.exit(1)
        else:
            if not auth.org:
                console.print(MSG_NO_AUTHD_CICD_PROD_STG_ORG.format(LOGIN_URL=CLI_AUTH))

            else:
                console.print(MSG_NO_AUTHD_CICD_PROD_STG)
                console.print(
                    MSG_NO_AUTHD_NOTE_CICD_PROD_STG_TPL.format(
                        LOGIN_URL=CLI_AUTH, SIGNUP_URL=f"{CLI_AUTH}/?sign_up=True"
                    )
                )
            sys.exit(1)

    elif not auth.email_verified:
        console.print()
        console.print(
            MSG_NO_VERIFIED_EMAIL_TPL.format(
                email=auth.email if auth.email else "Missing email"
            )
        )
        sys.exit(1)
    else:
        console.print(MSG_NON_AUTHENTICATED)
        sys.exit(1)


class CustomContext(click.Context):
    def __init__(
        self,
        command: "Command",
        parent: Optional["Context"] = None,
        command_type: CommandType = CommandType.MAIN,
        feature_type: Optional[FeatureType] = None,
        **kwargs,
    ) -> None:
        self.command_type = command_type
        self.feature_type = feature_type
        self.started_at = time.monotonic()
        self.command_alias_used: Optional[str] = None
        super().__init__(command, parent=parent, **kwargs)


class SafetyCLISubGroup(TyperGroup):
    """
    Custom TyperGroup with additional functionality for Safety CLI.
    """

    context_class = CustomContext

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """
        Format help message with rich formatting.

        Args:
            ctx (click.Context): Click context.
            formatter (click.HelpFormatter): Click help formatter.
        """
        pretty_format_help(self, ctx, markup_mode=self.rich_markup_mode)

    def format_usage(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """
        Format usage message.

        Args:
            ctx (click.Context): Click context.
            formatter (click.HelpFormatter): Click help formatter.
        """
        command_path = ctx.command_path
        pieces = self.collect_usage_pieces(ctx)
        main_group = ctx.parent
        if main_group:
            command_path = (
                f"{main_group.command_path} [GLOBAL-OPTIONS] {ctx.command.name}"
            )

        formatter.write_usage(command_path, " ".join(pieces))

    def command(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> click.Command:  # type: ignore[override]
        """
        Create a new command.

        Args:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            click.Command: The created command.
        """
        super().command(*args, **kwargs)


class SafetyCLICommand(TyperCommand):
    """
    Custom TyperCommand with additional functionality for Safety CLI.
    """

    context_class = CustomContext

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """
        Format help message with rich formatting.

        Args:
            ctx (click.Context): Click context.
            formatter (click.HelpFormatter): Click help formatter.
        """
        pretty_format_help(self, ctx, markup_mode=self.rich_markup_mode)

    def format_usage(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """
        Format usage message.

        Args:
            ctx (click.Context): Click context.
            formatter (click.HelpFormatter): Click help formatter.
        """
        command_path = ctx.command_path
        pieces = self.collect_usage_pieces(ctx)
        main_group = ctx.parent
        if main_group:
            command_path = (
                f"{main_group.command_path} [GLOBAL-OPTIONS] {ctx.command.name}"
            )

        formatter.write_usage(command_path, " ".join(pieces))


class SafetyCLILegacyGroup(click.Group):
    """
    Custom Click Group to handle legacy command-line arguments.
    """

    context_class = CustomContext

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.all_commands = {}

    def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)

    def add_command(self, cmd, name=None) -> None:
        super().add_command(cmd, name)

        name = name or cmd.name
        self.all_commands[name] = cmd

    def parse_args(self, ctx: click.Context, args: List[str]) -> List[str]:
        ctx = cast(CustomContext, ctx)

        if len(args) >= 1:
            if "pip" in args[0] and ctx:
                ctx.command_alias_used = args[0]
                args[0] = "pip"

        parsed_args = super().parse_args(ctx, args)

        args = ctx.args

        # Workaround for legacy check options, that now are global options
        subcommand_args = set(args)
        PROXY_HOST_OPTIONS = set(["--proxy-host", "-ph"])
        if (
            "check" in ctx.protected_args
            or "license" in ctx.protected_args
            and (
                bool(
                    PROXY_HOST_OPTIONS.intersection(subcommand_args)
                    or "--key" in subcommand_args
                )
            )
        ):
            proxy_options, key = self.parse_legacy_args(args)
            if proxy_options:
                ctx.params.update(proxy_options)

            if key:
                ctx.params.update({"key": key})

        return parsed_args

    def parse_legacy_args(
        self, args: List[str]
    ) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
        """
        Parse legacy command-line arguments for proxy settings and keys.

        Args:
            args (List[str]): List of command-line arguments.

        Returns:
            Tuple[Optional[Dict[str, str]], Optional[str]]: Parsed proxy options and key.
        """
        options = {"proxy_protocol": "https", "proxy_port": 80, "proxy_host": None}
        key = None

        for i, arg in enumerate(args):
            if arg in ["--proxy-protocol", "-pr"] and i + 1 < len(args):
                options["proxy_protocol"] = args[i + 1]
            elif arg in ["--proxy-port", "-pp"] and i + 1 < len(args):
                options["proxy_port"] = int(args[i + 1])
            elif arg in ["--proxy-host", "-ph"] and i + 1 < len(args):
                options["proxy_host"] = args[i + 1]
            elif arg in ["--key"] and i + 1 < len(args):
                key = args[i + 1]

        proxy = options if options["proxy_host"] else None
        return proxy, key

    def get_filtered_commands(self, ctx: click.Context) -> Dict[str, click.Command]:
        from safety.auth.utils import initialize

        initialize(ctx, refresh=False)

        # Filter commands here:
        from .constants import CONTEXT_FEATURE_TYPE

        disabled_features = [
            feature_type
            for feature_type in FeatureType
            if not getattr(ctx.obj, feature_type.attr_name, False)
        ]

        return {
            k: v
            for k, v in self.commands.items()
            if v.context_settings.get(CONTEXT_FEATURE_TYPE, None)
            not in disabled_features
            or k in ["firewall"]
        }

    def invoke(self, ctx: click.Context) -> None:
        """
        Invoke the command, handling legacy arguments.

        Args:
            ctx (click.Context): Click context.
        """
        session_kwargs = {
            "ctx": ctx,
            "proxy_protocol": ctx.params.pop("proxy_protocol", None),
            "proxy_host": ctx.params.pop("proxy_host", None),
            "proxy_port": ctx.params.pop("proxy_port", None),
            "key": ctx.params.pop("key", None),
            "stage": ctx.params.pop("stage", None),
        }
        invoked_command = make_str(next(iter(ctx.protected_args), ""))

        from safety.auth.cli_utils import inject_session

        inject_session(**session_kwargs, invoked_command=invoked_command)

        # call initialize if the --key is used.
        if session_kwargs["key"]:
            from safety.auth.utils import initialize

            initialize(ctx, refresh=True)

        self.commands = self.get_filtered_commands(ctx)

        # Now, invoke the original behavior
        super(SafetyCLILegacyGroup, self).invoke(ctx)

    def list_commands(self, ctx: click.Context) -> List[str]:
        """Override click.Group.list_commands with custom filtering"""
        self.commands = self.get_filtered_commands(ctx)

        return super().list_commands(ctx)

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """
        Format help message with rich formatting.

        Args:
            ctx (click.Context): Click context.
            formatter (click.HelpFormatter): Click help formatter.
        """
        # The main `safety --help`
        if self.name == "cli":
            format_main_help(self, ctx, markup_mode="rich")
        # All other help outputs
        else:
            pretty_format_help(self, ctx, markup_mode="rich")


class SafetyCLILegacyCommand(click.Command):
    """
    Custom Click Command to handle legacy command-line arguments.
    """

    context_class = CustomContext

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        """
        Format help message with rich formatting.

        Args:
            ctx (click.Context): Click context.
            formatter (click.HelpFormatter): Click help formatter.
        """
        pretty_format_help(self, ctx, markup_mode="rich")


def get_git_branch_name() -> Optional[str]:
    """
    Retrieves the current Git branch name.

    Returns:
        str: The current Git branch name, or None if it cannot be determined.
    """
    try:
        branch_name = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return branch_name if branch_name else None
    except Exception:
        return None
