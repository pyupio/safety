# -*- coding: utf-8 -*-
# type: ignore
from __future__ import absolute_import

import configparser
import json
import logging
import os
import platform
import sys
import time
from dataclasses import asdict
from datetime import date, datetime, timedelta
from enum import Enum
from functools import wraps
from pathlib import Path

import click
import requests
import typer
import typer.rich_utils
from packaging import version as packaging_version
from packaging.version import InvalidVersion
from safety_schemas.config.schemas.v3_0 import main as v3_0
from safety_schemas.models import (
    ConfigModel,
    Ecosystem,
    Stage,
    VulnerabilitySeverityLabels,
)

from safety.alerts import alert
from safety.auth import auth_options, proxy_options
from safety.auth.cli import auth_app
from safety.auth.models import Organization
from safety.decorators import notify
from safety.codebase.command import codebase_app
from safety.console import main_console as console
from safety.constants import (
    BAR_LINE,
    CONFIG_FILE_SYSTEM,
    CONFIG_FILE_USER,
    CONTEXT_COMMAND_TYPE,
    EXIT_CODE_FAILURE,
    EXIT_CODE_OK,
    EXIT_CODE_VULNERABILITIES_FOUND,
    CLI_MAIN_INTRODUCTION,
    DEFAULT_EPILOG,
)
from safety.error_handlers import handle_cmd_exception, output_exception
from safety.errors import InvalidCredentialError, SafetyError, SafetyException
from safety.firewall.command import firewall_app
from safety.formatter import SafetyFormatter
from safety.init.command import init_app
from safety.meta import get_version
from safety.output_utils import should_add_nl
from safety.tool import tool_commands
from safety.scan.command import scan_project_app, scan_system_app
from safety.scan.constants import (
    CLI_CHECK_COMMAND_HELP,
    CLI_CHECK_UPDATES_HELP,
    CLI_CONFIGURE_HELP,
    CLI_CONFIGURE_ORGANIZATION_ID,
    CLI_CONFIGURE_ORGANIZATION_NAME,
    CLI_CONFIGURE_PROXY_HOST_HELP,
    CLI_CONFIGURE_PROXY_PORT_HELP,
    CLI_CONFIGURE_PROXY_PROTOCOL_HELP,
    CLI_CONFIGURE_PROXY_REQUIRED,
    CLI_CONFIGURE_PROXY_TIMEOUT,
    CLI_CONFIGURE_SAVE_TO_SYSTEM,
    CLI_DEBUG_HELP,
    CLI_DISABLE_OPTIONAL_TELEMETRY_DATA_HELP,
    CLI_GENERATE_HELP,
    CLI_GENERATE_MINIMUM_CVSS_SEVERITY,
    CLI_GENERATE_PATH,
    CLI_LICENSES_COMMAND_HELP,
    DEFAULT_SPINNER,
)
from safety.scan.finder import FileFinder
from safety.scan.main import process_files
from safety.util import (
    DependentOption,
    MutuallyExclusiveOption,
    SafetyContext,
    SafetyPolicyFile,
    active_color_if_needed,
    bare_alias,
    filter_announcements,
    get_fix_options,
    get_packages_licenses,
    get_processed_options,
    html_alias,
    initialize_config_dirs,
    initialize_event_bus,
    is_a_remote_mirror,
    json_alias,
    transform_ignore,
)

from .cli_util import (
    CommandType,
    SafetyCLICommand,
    SafetyCLILegacyCommand,
    SafetyCLILegacyGroup,
    SafetyCLISubGroup,
)

from safety import safety as safety_core

try:
    from typing import Annotated, Optional
except ImportError:
    from typing_extensions import Annotated, Optional


import safety.asyncio_patch  # noqa: F401

LOG = logging.getLogger(__name__)


def get_network_telemetry():
    import psutil
    import socket

    network_info = {}
    try:
        # Get network IO statistics
        net_io = psutil.net_io_counters()
        network_info["bytes_sent"] = net_io.bytes_sent
        network_info["bytes_recv"] = net_io.bytes_recv
        network_info["packets_sent"] = net_io.packets_sent
        network_info["packets_recv"] = net_io.packets_recv

        # Test network speed (download speed)
        test_url = "https://data.safetycli.com/api/v1/safety/announcements/"  # Test the download speed
        start_time = time.perf_counter()
        try:
            response = requests.get(test_url, timeout=10)
            end_time = time.perf_counter()
            download_time = end_time - start_time
            download_speed = len(response.content) / download_time
            network_info["download_speed"] = download_speed
        except requests.RequestException as e:
            network_info["download_speed"] = None
            network_info["error"] = str(e)

        # Get network addresses
        net_if_addrs = psutil.net_if_addrs()
        network_info["interfaces"] = {
            iface: [addr.address for addr in addrs if addr.family == socket.AF_INET]
            for iface, addrs in net_if_addrs.items()
        }

        # Get network connections
        net_connections = psutil.net_connections(kind="inet")
        network_info["connections"] = [
            {
                "fd": conn.fd,
                "family": conn.family,
                "type": conn.type,
                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}",
                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
            }
            for conn in net_connections
        ]

        # Get network interface stats
        net_if_stats = psutil.net_if_stats()
        network_info["interface_stats"] = {
            iface: {
                "isup": stats.isup,
                "duplex": stats.duplex,
                "speed": stats.speed,
                "mtu": stats.mtu,
            }
            for iface, stats in net_if_stats.items()
        }
    except psutil.AccessDenied as e:
        network_info["error"] = (
            f"Access denied when trying to gather network telemetry: {e}"
        )

    return network_info


def preprocess_args(f):
    if "--debug" in sys.argv:
        index = sys.argv.index("--debug")
        if len(sys.argv) > index + 1:
            next_arg = sys.argv[index + 1]
            if next_arg in ("1", "true"):
                sys.argv.pop(index + 1)  # Remove the next argument (1 or true)
    return f


def configure_logger(ctx, param, debug):
    level = logging.CRITICAL

    if debug:
        level = logging.DEBUG

    logging.basicConfig(format="%(asctime)s %(name)s => %(message)s", level=level)

    if debug:
        # Log the contents of the config.ini file
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE_USER)
        LOG.debug("Config file contents:")
        for section in config.sections():
            LOG.debug("[%s]", section)
            for key, value in config.items(section):
                LOG.debug("%s = %s", key, value)

        # Log the proxy settings if they were attempted
        if "proxy" in config:
            LOG.debug(
                "Proxy configuration attempted with settings: %s", dict(config["proxy"])
            )

        # Collect and log network telemetry data
        network_telemetry = get_network_telemetry()
        LOG.debug("Network telemetry: %s", network_telemetry)


@click.group(
    cls=SafetyCLILegacyGroup, help=CLI_MAIN_INTRODUCTION, epilog=DEFAULT_EPILOG
)
@auth_options()
@proxy_options
@click.option(
    "--disable-optional-telemetry",
    default=False,
    is_flag=True,
    show_default=True,
    help=CLI_DISABLE_OPTIONAL_TELEMETRY_DATA_HELP,
)
@click.option("--debug", is_flag=True, help=CLI_DEBUG_HELP, callback=configure_logger)
@click.version_option(version=get_version())
@click.pass_context
@preprocess_args
def cli(ctx, debug, disable_optional_telemetry):
    """
    Scan and secure Python projects against package vulnerabilities. To get started navigate to a Python project and run `safety scan`.
    """
    SafetyContext().safety_source = "cli"
    telemetry = not disable_optional_telemetry
    ctx.obj.config = ConfigModel(telemetry_enabled=telemetry)
    level = logging.CRITICAL
    if debug:
        level = logging.DEBUG

    logging.basicConfig(format="%(asctime)s %(name)s => %(message)s", level=level)

    LOG.info(f"Telemetry enabled: {ctx.obj.config.telemetry_enabled}")

    # Before any command make sure that the parent dirs for Safety config are present.
    initialize_config_dirs()

    initialize_event_bus(ctx=ctx)


def clean_check_command(f):
    """
    Main entry point for validation.
    """

    @wraps(f)
    def inner(ctx, *args, **kwargs):
        save_json = kwargs["save_json"]
        output = kwargs["output"]
        authenticated: bool = ctx.obj.auth.client.is_using_auth_credentials()
        files = kwargs["files"]
        policy_file = kwargs["policy_file"]
        auto_remediation_limit = kwargs["auto_remediation_limit"]
        audit_and_monitor = kwargs["audit_and_monitor"]
        exit_code = kwargs["exit_code"]

        # This is handled in the custom subgroup Click class
        # TODO: Remove this soon, for now it keeps a legacy behavior
        kwargs.pop("key", None)
        kwargs.pop("proxy_protocol", None)
        kwargs.pop("proxy_host", None)
        kwargs.pop("proxy_port", None)

        if ctx.get_parameter_source(
            "json_version"
        ) != click.core.ParameterSource.DEFAULT and not (
            save_json or json or output == "json"
        ):
            raise click.UsageError(
                "Illegal usage: `--json-version` only works with JSON related outputs."
            )

        try:
            if (
                ctx.get_parameter_source("apply_remediations")
                != click.core.ParameterSource.DEFAULT
            ):
                if not authenticated:
                    raise InvalidCredentialError(
                        message="The --apply-security-updates option needs authentication. See {link}."
                    )
                if not files:
                    raise SafetyError(
                        message='--apply-security-updates only works with files; use the "-r" option to '
                        "specify files to remediate."
                    )

            auto_remediation_limit = get_fix_options(
                policy_file, auto_remediation_limit
            )
            policy_file, server_audit_and_monitor = safety_core.get_server_policies(
                ctx.obj.auth.client, policy_file=policy_file, proxy_dictionary=None
            )
            audit_and_monitor = audit_and_monitor and server_audit_and_monitor

            kwargs.update(
                {
                    "auto_remediation_limit": auto_remediation_limit,
                    "policy_file": policy_file,
                    "audit_and_monitor": audit_and_monitor,
                }
            )

        except SafetyError as e:
            LOG.exception("Expected SafetyError happened: %s", e)
            output_exception(e, exit_code_output=exit_code)
        except Exception as e:
            LOG.exception("Unexpected Exception happened: %s", e)
            exception = e if isinstance(e, SafetyException) else SafetyException(info=e)
            output_exception(exception, exit_code_output=exit_code)

        return f(ctx, *args, **kwargs)

    return inner


def print_deprecation_message(
    old_command: str, deprecation_date: datetime, new_command: Optional[str] = None
) -> None:
    """
    Print a formatted deprecation message for a command.

    This function uses the click library to output a visually distinct
    message in the console, warning users about the deprecation of a
    specified command. It includes information about the deprecation date
    and suggests an alternative command to use, if provided.

    The message is formatted with colors and styles for emphasis:
    - Yellow for the border and general information
    - Red for the 'DEPRECATED' label
    - Green for the suggestion of the new command (if provided)

    Parameters:
    - old_command (str): The name of the deprecated command.
    - deprecation_date (datetime): The date when the command will no longer be supported.
    - new_command (str, optional): The name of the alternative command to suggest. Default is None.
    """
    click.echo("\n")
    click.echo(click.style(BAR_LINE, fg="yellow", bold=True))
    click.echo("\n")
    click.echo(
        click.style("DEPRECATED: ", fg="red", bold=True)
        + click.style(
            f"this command (`{old_command}`) has been DEPRECATED, and will be unsupported beyond {deprecation_date.strftime('%d %B %Y')}.",
            fg="yellow",
            bold=True,
        )
    )

    if new_command:
        click.echo("\n")
        click.echo(
            click.style("We highly encourage switching to the new ", fg="green")
            + click.style(f"`{new_command}`", fg="green", bold=True)
            + click.style(
                " command which is easier to use, more powerful, and can be set up to mimic the deprecated command if required.",
                fg="green",
            )
        )

    click.echo("\n")
    click.echo(click.style(BAR_LINE, fg="yellow", bold=True))
    click.echo("\n")


@cli.command(
    cls=SafetyCLILegacyCommand,
    context_settings={CONTEXT_COMMAND_TYPE: CommandType.UTILITY},
    help=CLI_CHECK_COMMAND_HELP,
)
@proxy_options
@auth_options(stage=False)
@click.option(
    "--db",
    default="",
    help="Path to a local or remote vulnerability database. Default: empty",
)
@click.option(
    "--full-report/--short-report",
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["output", "json", "bare"],
    with_values={
        "output": ["json", "bare"],
        "json": [True, False],
        "html": [True, False],
        "bare": [True, False],
    },
    help="Full reports include a security advisory (if available). Default: --short-report",
)
@click.option(
    "--cache",
    is_flag=False,
    flag_value=60,
    default=0,
    help="Cache requests to the vulnerability database locally. Default: 0 seconds",
    hidden=True,
)
@click.option(
    "--stdin",
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["files"],
    help="Read input from stdin.",
    is_flag=True,
    show_default=True,
)
@click.option(
    "files",
    "--file",
    "-r",
    multiple=True,
    type=click.File(),
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["stdin"],
    help="Read input from one (or multiple) requirement files. Default: empty",
)
@click.option(
    "--ignore",
    "-i",
    multiple=True,
    type=str,
    default=[],
    callback=transform_ignore,
    help="Ignore one (or multiple) vulnerabilities by ID (coma separated). Default: empty",
)
@click.option(
    "ignore_unpinned_requirements",
    "--ignore-unpinned-requirements/--check-unpinned-requirements",
    "-iur",
    default=None,
    help="Check or ignore unpinned requirements found.",
)
@click.option(
    "--json",
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["output", "bare"],
    with_values={
        "output": ["screen", "text", "bare", "json", "html"],
        "bare": [True, False],
    },
    callback=json_alias,
    hidden=True,
    is_flag=True,
    show_default=True,
)
@click.option(
    "--html",
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["output", "bare"],
    with_values={
        "output": ["screen", "text", "bare", "json", "html"],
        "bare": [True, False],
    },
    callback=html_alias,
    hidden=True,
    is_flag=True,
    show_default=True,
)
@click.option(
    "--bare",
    default=False,
    cls=MutuallyExclusiveOption,
    mutually_exclusive=["output", "json"],
    with_values={"output": ["screen", "text", "bare", "json"], "json": [True, False]},
    callback=bare_alias,
    hidden=True,
    is_flag=True,
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["screen", "text", "json", "bare", "html"], case_sensitive=False),
    default="screen",
    callback=active_color_if_needed,
    envvar="SAFETY_OUTPUT",
)
@click.option(
    "--exit-code/--continue-on-error",
    default=True,
    help="Output standard exit codes. Default: --exit-code",
)
@click.option(
    "--policy-file",
    type=SafetyPolicyFile(),
    default=".safety-policy.yml",
    help="Define the policy file to be used",
)
@click.option(
    "--audit-and-monitor/--disable-audit-and-monitor",
    default=True,
    help="Send results back to safetycli.com for viewing on your dashboard. Requires an API key.",
)
@click.option(
    "project",
    "--project-id",
    "--project",
    default=None,
    help="Project to associate this scan with on safetycli.com. "
    "Defaults to a canonicalized github style name if available, otherwise unknown",
)
@click.option(
    "--save-json",
    default="",
    help="Path to where the output file will be placed; if the path is a"
    " directory, Safety will use safety-report.json as filename."
    " Default: empty",
)
@click.option(
    "--save-html",
    default="",
    help="Path to where the output file will be placed; if the path is a"
    " directory, Safety will use safety-report.html as the main file. "
    "Default: empty",
)
@click.option(
    "apply_remediations",
    "--apply-security-updates",
    "-asu",
    default=False,
    is_flag=True,
    help="Apply security updates in your requirement files.",
)
@click.option(
    "auto_remediation_limit",
    "--auto-security-updates-limit",
    "-asul",
    multiple=True,
    type=click.Choice(["patch", "minor", "major"]),
    default=["patch"],
    help="Define the limit to be used for automatic security updates in your requirement files."
    " Default: patch",
)
@click.option(
    "no_prompt",
    "--no-prompt",
    "-np",
    default=False,
    help="Safety won't ask for remediations outside of the remediation limit.",
    is_flag=True,
    show_default=True,
)
@click.option(
    "json_version",
    "--json-output-format",
    type=click.Choice(["0.5", "1.1"]),
    default="1.1",
    help="Select the JSON version to be used in the output",
    show_default=True,
)
@click.pass_context
@clean_check_command
@handle_cmd_exception
@notify
def check(
    ctx,
    db,
    full_report,
    stdin,
    files,
    cache,
    ignore,
    ignore_unpinned_requirements,
    output,
    json,
    html,
    bare,
    exit_code,
    policy_file,
    audit_and_monitor,
    project,
    save_json,
    save_html,
    apply_remediations,
    auto_remediation_limit,
    no_prompt,
    json_version,
):
    """
    [underline][DEPRECATED][/underline] `check` has been replaced by the `scan` command, and will be unsupported beyond 1 June 2024.Find vulnerabilities at a target file or enviroment.
    """
    LOG.info("Running check command")

    non_interactive = (
        not sys.stdout.isatty()
        and os.environ.get("SAFETY_OS_DESCRIPTION", None) != "run"
    )
    silent_outputs = ["json", "bare", "html"]
    is_silent_output = output in silent_outputs
    prompt_mode = (
        bool(not non_interactive and not stdin and not is_silent_output)
        and not no_prompt
    )
    kwargs = {"version": json_version} if output == "json" else {}
    print_deprecation_message("check", date(2024, 6, 1), new_command="scan")
    # try:
    packages = safety_core.get_packages(files, stdin)

    ignore_severity_rules = None
    ignore, ignore_severity_rules, exit_code, ignore_unpinned_requirements, project = (
        get_processed_options(
            policy_file,
            ignore,
            ignore_severity_rules,
            exit_code,
            ignore_unpinned_requirements,
            project,
        )
    )
    is_env_scan = not stdin and not files

    params = {
        "stdin": stdin,
        "files": files,
        "policy_file": policy_file,
        "continue_on_error": not exit_code,
        "ignore_severity_rules": ignore_severity_rules,
        "project": project,
        "audit_and_monitor": audit_and_monitor,
        "prompt_mode": prompt_mode,
        "auto_remediation_limit": auto_remediation_limit,
        "apply_remediations": apply_remediations,
        "ignore_unpinned_requirements": ignore_unpinned_requirements,
    }

    LOG.info("Calling the check function")
    vulns, db_full = safety_core.check(
        session=ctx.obj.auth.client,
        packages=packages,
        db_mirror=db,
        cached=cache,
        ignore_vulns=ignore,
        ignore_severity_rules=ignore_severity_rules,
        proxy=None,
        include_ignored=True,
        is_env_scan=is_env_scan,
        telemetry=ctx.obj.config.telemetry_enabled,
        params=params,
    )
    LOG.debug("Vulnerabilities returned: %s", vulns)
    LOG.debug("full database returned is None: %s", db_full is None)

    LOG.info("Safety is going to calculate remediations")

    remediations = safety_core.calculate_remediations(vulns, db_full)

    announcements = []
    if not db or is_a_remote_mirror(db):
        LOG.info("Not local DB used, Getting announcements")
        announcements = safety_core.get_announcements(
            ctx.obj.auth.client, telemetry=ctx.obj.config.telemetry_enabled
        )

    announcements.extend(
        safety_core.add_local_notifications(packages, ignore_unpinned_requirements)
    )

    LOG.info(
        "Safety is going to render the vulnerabilities report using %s output", output
    )

    fixes = []

    if apply_remediations and is_silent_output:
        # it runs and apply only automatic fixes.
        fixes = safety_core.process_fixes(
            files,
            remediations,
            auto_remediation_limit,
            output,
            no_output=True,
            prompt=False,
        )

    output_report = SafetyFormatter(output, **kwargs).render_vulnerabilities(
        announcements, vulns, remediations, full_report, packages, fixes
    )

    # Announcements are send to stderr if not terminal, it doesn't depend on "exit_code" value
    stderr_announcements = filter_announcements(
        announcements=announcements, by_type="error"
    )
    if stderr_announcements and non_interactive:
        LOG.info(
            "sys.stdout is not a tty, error announcements are going to be send to stderr"
        )
        click.secho(
            SafetyFormatter(output="text").render_announcements(stderr_announcements),
            fg="red",
            file=sys.stderr,
        )

    found_vulns = list(filter(lambda v: not v.ignored, vulns))
    LOG.info("Vulnerabilities found (Not ignored): %s", len(found_vulns))
    LOG.info("All vulnerabilities found (ignored and Not ignored): %s", len(vulns))

    click.secho(output_report, nl=should_add_nl(output, found_vulns), file=sys.stdout)

    post_processing_report = save_json or audit_and_monitor or apply_remediations

    if post_processing_report:
        if apply_remediations and not is_silent_output:
            # prompt_mode fixing after main check output if prompt is enabled.
            fixes = safety_core.process_fixes(
                files,
                remediations,
                auto_remediation_limit,
                output,
                no_output=False,
                prompt=prompt_mode,
            )

        # Render fixes
        json_report = (
            output_report
            if output == "json"
            else SafetyFormatter(
                output="json", version=json_version
            ).render_vulnerabilities(
                announcements, vulns, remediations, full_report, packages, fixes
            )
        )

        safety_core.save_report(save_json, "safety-report.json", json_report)

    if save_html:
        html_report = (
            output_report
            if output == "html"
            else SafetyFormatter(output="html").render_vulnerabilities(
                announcements, vulns, remediations, full_report, packages, fixes
            )
        )

        safety_core.save_report(save_html, "safety-report.html", html_report)
    print_deprecation_message("check", date(2024, 6, 1), new_command="scan")
    if exit_code and found_vulns:
        LOG.info("Exiting with default code for vulnerabilities found")
        sys.exit(EXIT_CODE_VULNERABILITIES_FOUND)

    sys.exit(EXIT_CODE_OK)


def clean_license_command(f):
    """
    Main entry point for validation.
    """

    @wraps(f)
    def inner(ctx, *args, **kwargs):
        # TODO: Remove this soon, for now it keeps a legacy behavior
        kwargs.pop("key", None)
        kwargs.pop("proxy_protocol", None)
        kwargs.pop("proxy_host", None)
        kwargs.pop("proxy_port", None)

        return f(ctx, *args, **kwargs)

    return inner


@cli.command(
    cls=SafetyCLILegacyCommand,
    context_settings={CONTEXT_COMMAND_TYPE: CommandType.UTILITY},
    help=CLI_LICENSES_COMMAND_HELP,
)
@proxy_options
@auth_options(stage=False)
@click.option(
    "--db", default="", help="Path to a local license database. Default: empty"
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["screen", "text", "json", "bare"], case_sensitive=False),
    default="screen",
)
@click.option(
    "--cache",
    default=0,
    help="Whether license database file should be cached.Default: 0 seconds",
)
@click.option(
    "files",
    "--file",
    "-r",
    multiple=True,
    type=click.File(),
    help="Read input from one (or multiple) requirement files. Default: empty",
)
@click.pass_context
@clean_license_command
@handle_cmd_exception
@notify
def license(ctx, db, output, cache, files):
    """
    Find the open source licenses used by your Python dependencies.
    """
    print_deprecation_message("license", date(2024, 6, 1), new_command=None)
    LOG.info("Running license command")
    packages = safety_core.get_packages(files, False)
    licenses_db = {}

    SafetyContext().params = ctx.params

    licenses_db = safety_core.get_licenses(
        session=ctx.obj.auth.client,
        db_mirror=db,
        cached=cache,
        telemetry=ctx.obj.config.telemetry_enabled,
    )

    filtered_packages_licenses = get_packages_licenses(
        packages=packages, licenses_db=licenses_db
    )

    announcements = []
    if not db:
        announcements = safety_core.get_announcements(
            session=ctx.obj.auth.client, telemetry=ctx.obj.config.telemetry_enabled
        )

    output_report = SafetyFormatter(output=output).render_licenses(
        announcements, filtered_packages_licenses
    )

    click.secho(output_report, nl=True)
    print_deprecation_message("license", date(2024, 6, 1), new_command=None)


@cli.command(
    cls=SafetyCLILegacyCommand,
    context_settings={CONTEXT_COMMAND_TYPE: CommandType.UTILITY},
    help=CLI_GENERATE_HELP,
)
@click.option("--path", default=".", help=CLI_GENERATE_PATH)
@click.option(
    "--minimum-cvss-severity",
    default="critical",
    help=CLI_GENERATE_MINIMUM_CVSS_SEVERITY,
)
@click.argument("name", required=True)
@click.pass_context
@handle_cmd_exception
@notify
def generate(ctx, name, path, minimum_cvss_severity):
    """Create a boilerplate Safety CLI policy file

    NAME is the name of the file type to generate. Valid values are: policy_file
    """
    if name != "policy_file" and name != "installation_policy":
        click.secho(
            f'This Safety version only supports "policy_file" generation. "{name}" is not supported.',
            fg="red",
            file=sys.stderr,
        )
        sys.exit(EXIT_CODE_FAILURE)

    LOG.info("Running generate %s", name)

    if name == "policy_file":
        generate_policy_file(name, path)
    elif name == "installation_policy":
        generate_installation_policy(ctx, name, path, minimum_cvss_severity)


def generate_installation_policy(ctx, name, path, minimum_cvss_severity):
    all_severities = [severity.name.lower() for severity in VulnerabilitySeverityLabels]
    policy_severities = all_severities[
        all_severities.index(minimum_cvss_severity.lower()) :
    ]
    policy_severities_set = set(policy_severities[:])

    target = path

    ecosystems = [Ecosystem.PYTHON]
    to_include = {
        file_type: paths
        for file_type, paths in ctx.obj.config.scan.include_files.items()
        if file_type.ecosystem in ecosystems
    }

    # Initialize file finder
    file_finder = FileFinder(
        target=target,
        ecosystems=ecosystems,
        max_level=ctx.obj.config.scan.max_depth,
        exclude=ctx.obj.config.scan.ignore,
        include_files=to_include,
    )

    for handler in file_finder.handlers:
        if handler.ecosystem:
            wait_msg = "Fetching Safety's vulnerability database..."
            with console.status(wait_msg, spinner=DEFAULT_SPINNER):
                handler.download_required_assets(ctx.obj.auth.client)

    wait_msg = "Scanning project directory"
    with console.status(wait_msg, spinner=DEFAULT_SPINNER):
        path, file_paths = file_finder.search()

    target_ecosystems = ", ".join([member.value for member in ecosystems])
    wait_msg = (
        f"Analyzing {target_ecosystems} files and environments for security findings"
    )

    config = ctx.obj.config

    vulnerabilities = []
    with console.status(wait_msg, spinner=DEFAULT_SPINNER):
        for path, analyzed_file in process_files(paths=file_paths, config=config):
            affected_specifications = (
                analyzed_file.dependency_results.get_affected_specifications()
            )
            if any(affected_specifications):
                for spec in affected_specifications:
                    for vuln in spec.vulnerabilities:
                        if (
                            vuln.severity
                            and vuln.severity.cvssv3
                            and vuln.severity.cvssv3.get(
                                "base_severity", "none"
                            ).lower()
                            in policy_severities_set
                        ):
                            vulnerabilities.append(vuln)

    policy = v3_0.Config(
        installation=v3_0.Installation(
            default_action=v3_0.InstallationAction.ALLOW,
            allow=v3_0.AllowedInstallation(
                packages=None,
                vulnerabilities={
                    vuln.vulnerability_id: v3_0.IgnoredVulnerability(
                        reason=f"Autogenerated policy for {vuln.package_name} package.",
                        expires=date.today() + timedelta(days=90),
                    )
                    for vuln in vulnerabilities
                },
            ),
            deny=v3_0.DeniedInstallation(
                packages=None,
                vulnerabilities=v3_0.DeniedVulnerability(
                    block_on_any_of=v3_0.DeniedVulnerabilityCriteria(
                        cvss_severity=policy_severities
                    )
                ),
            ),
        )
    )

    click.secho(policy.json(by_alias=True, exclude_none=True, indent=4))


def generate_policy_file(name, path):
    path = Path(path)
    if not path.exists():
        click.secho(f'The path "{path}" does not exist.', fg="red", file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)
    policy = path / ".safety-policy.yml"
    default_config = ConfigModel()
    try:
        default_config.save_policy_file(policy)
        LOG.debug("Safety created the policy file.")
        msg = (
            f"A default Safety policy file has been generated! Review the file contents in the path {path} in the "
            "file: .safety-policy.yml"
        )
        click.secho(msg, fg="green")
    except Exception as exc:
        if isinstance(exc, OSError):
            LOG.debug("Unable to generate %s because: %s", name, exc.errno)

        click.secho(f"{str(exc)} error.", fg="red", file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)


@cli.command(
    cls=SafetyCLILegacyCommand,
    context_settings={CONTEXT_COMMAND_TYPE: CommandType.UTILITY},
)
@click.option(
    "--path",
    default=".safety-policy.yml",
    help="Path where the generated file will be saved. Default: current directory",
)
@click.argument("name")
@click.argument("version", required=False)
@click.pass_context
@handle_cmd_exception
@notify
def validate(ctx, name, version, path):
    """Verify that a local policy file is valid. NAME is the name of the file type to validate. Valid values are: policy_file"""
    if name != "policy_file":
        click.secho(
            f'This Safety version only supports "policy_file" validation. "{name}" is not supported.',
            fg="red",
            file=sys.stderr,
        )
        sys.exit(EXIT_CODE_FAILURE)

    LOG.info("Running validate %s", name)

    if not os.path.exists(path):
        click.secho(f'The path "{path}" does not exist.', fg="red", file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)

    if version not in ["3.0", "2.0", None]:
        click.secho(
            f'Version "{version}" is not a valid value, allowed values are 3.0 and 2.0. Use --path to specify the target file.',
            fg="red",
            file=sys.stderr,
        )
        sys.exit(EXIT_CODE_FAILURE)

    def fail_validation(e):
        click.secho(str(e).lstrip(), fg="red", file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)

    if not version:
        version = "3.0"

    result = ""

    if version == "3.0":
        policy = None

        try:
            from .scan.main import load_policy_file

            policy = load_policy_file(Path(path))
        except Exception as e:
            fail_validation(e)

        click.secho(
            f"The Safety policy ({version}) file "
            "(Used for scan and system-scan commands) "
            "was successfully parsed "
            "with the following values:",
            fg="green",
        )
        if policy and policy.config:
            result = policy.config.as_v30().json()
    else:
        try:
            values = SafetyPolicyFile().convert(path, None, None)
        except Exception as e:
            click.secho(str(e).lstrip(), fg="red", file=sys.stderr)
            sys.exit(EXIT_CODE_FAILURE)

        del values["raw"]

        result = json.dumps(values, indent=4, default=str)

        click.secho(
            "The Safety policy file "
            "(Valid only for the check command) "
            "was successfully parsed with the "
            "following values:",
            fg="green",
        )

    console.print_json(result)


@cli.command(
    cls=SafetyCLILegacyCommand,
    help=CLI_CONFIGURE_HELP,
    context_settings={CONTEXT_COMMAND_TYPE: CommandType.UTILITY},
)
@click.option(
    "--proxy-protocol",
    "-pr",
    type=click.Choice(["http", "https"]),
    default="https",
    cls=DependentOption,
    required_options=["proxy_host"],
    help=CLI_CONFIGURE_PROXY_PROTOCOL_HELP,
)
@click.option(
    "--proxy-host",
    "-ph",
    multiple=False,
    type=str,
    default=None,
    help=CLI_CONFIGURE_PROXY_HOST_HELP,
)
@click.option(
    "--proxy-port",
    "-pp",
    multiple=False,
    type=int,
    default=80,
    cls=DependentOption,
    required_options=["proxy_host"],
    help=CLI_CONFIGURE_PROXY_PORT_HELP,
)
@click.option(
    "--proxy-timeout",
    "-pt",
    multiple=False,
    type=int,
    default=None,
    help=CLI_CONFIGURE_PROXY_TIMEOUT,
)
@click.option("--proxy-required", default=False, help=CLI_CONFIGURE_PROXY_REQUIRED)
@click.option(
    "--organization-id",
    "-org-id",
    multiple=False,
    default=None,
    cls=DependentOption,
    required_options=["organization_name"],
    help=CLI_CONFIGURE_ORGANIZATION_ID,
)
@click.option(
    "--organization-name",
    "-org-name",
    multiple=False,
    default=None,
    cls=DependentOption,
    required_options=["organization_id"],
    help=CLI_CONFIGURE_ORGANIZATION_NAME,
)
@click.option(
    "--stage",
    "-stg",
    multiple=False,
    default=Stage.development.value,
    type=click.Choice([stage.value for stage in Stage]),
    help="The project development stage to be tied to the current device.",
)
@click.option(
    "--save-to-system/--save-to-user",
    default=False,
    is_flag=True,
    help=CLI_CONFIGURE_SAVE_TO_SYSTEM,
)
@click.pass_context
@handle_cmd_exception
@notify
def configure(
    ctx,
    proxy_protocol,
    proxy_host,
    proxy_port,
    proxy_timeout,
    proxy_required,
    organization_id,
    organization_name,
    stage,
    save_to_system,
):
    """
    Configure global settings, like proxy settings and organization details
    """

    config = configparser.ConfigParser()
    if save_to_system:
        if not CONFIG_FILE_SYSTEM:
            click.secho(
                "Unable to determine the system wide config path. You can set the SAFETY_SYSTEM_CONFIG_PATH env var"
            )
            sys.exit(1)

        CONFIG_FILE = CONFIG_FILE_SYSTEM
    else:
        CONFIG_FILE = CONFIG_FILE_USER

    config.read(CONFIG_FILE)

    PROXY_SECTION_NAME: str = "proxy"
    PROXY_TIMEOUT_KEY: str = "timeout"
    PROXY_REQUIRED_KEY: str = "required"

    if organization_id:
        config["organization"] = asdict(
            Organization(id=organization_id, name=organization_name)
        )

    DEFAULT_PROXY_TIMEOUT: int = 500

    if not proxy_timeout:
        try:
            proxy_timeout = int(config["proxy"]["timeout"])
        except Exception:
            proxy_timeout = DEFAULT_PROXY_TIMEOUT

    new_proxy_config = {}
    new_proxy_config.setdefault(PROXY_TIMEOUT_KEY, str(proxy_timeout))
    new_proxy_config.setdefault(PROXY_REQUIRED_KEY, str(proxy_required))

    if proxy_host:
        new_proxy_config.update(
            {"protocol": proxy_protocol, "host": proxy_host, "port": str(proxy_port)}
        )

    if not config.has_section(PROXY_SECTION_NAME):
        config.add_section(PROXY_SECTION_NAME)

    proxy_config = dict(config.items(PROXY_SECTION_NAME))
    proxy_config.update(new_proxy_config)

    for key, value in proxy_config.items():
        config.set(PROXY_SECTION_NAME, key, value)

    if stage:
        config["host"] = {"stage": "development" if stage == "dev" else stage}

    try:
        with open(CONFIG_FILE, "w") as configfile:
            config.write(configfile)
    except Exception as e:
        if (
            isinstance(e, OSError) and e.errno == 2 or e is PermissionError
        ) and save_to_system:
            click.secho(
                "Unable to save the configuration: writing to system-wide Safety configuration file requires admin privileges"
            )
        else:
            click.secho(f"Unable to save the configuration, error: {e}")
        sys.exit(1)


cli_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)
typer.rich_utils.STYLE_HELPTEXT = ""


def print_check_updates_header(console):
    VERSION = get_version()
    console.print(
        f"Safety {VERSION} checking for Safety version and configuration updates:"
    )


class Output(str, Enum):
    SCREEN = "screen"
    JSON = "json"


@cli_app.command(
    cls=SafetyCLICommand,
    help=CLI_CHECK_UPDATES_HELP,
    name="check-updates",
    epilog=DEFAULT_EPILOG,
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        CONTEXT_COMMAND_TYPE: CommandType.UTILITY,
    },
)
@handle_cmd_exception
@notify
def check_updates(
    ctx: typer.Context,
    version: Annotated[
        int,
        typer.Option(min=1),
    ] = 1,
    output: Annotated[
        Output, typer.Option(help="The main output generated by Safety CLI.")
    ] = Output.SCREEN,
):
    """
    Check for Safety CLI version updates
    """

    if output is Output.JSON:
        console.quiet = True

    print_check_updates_header(console)

    wait_msg = "Authenticating and checking for Safety CLI updates"

    VERSION = get_version()
    PYTHON_VERSION = platform.python_version()
    OS_TYPE = platform.system()

    authenticated = ctx.obj.auth.client.is_using_auth_credentials()
    data = None

    console.print()
    with console.status(wait_msg, spinner=DEFAULT_SPINNER):
        try:
            data = ctx.obj.auth.client.check_updates(
                version=1,
                safety_version=VERSION,
                python_version=PYTHON_VERSION,
                os_type=OS_TYPE,
                os_release=platform.release(),
                os_description=platform.platform(),
            )
        except InvalidCredentialError:
            authenticated = False
        except Exception as e:
            LOG.exception(f"Failed to check updates, reason: {e}")
            raise e

    if not authenticated:
        if console.quiet:
            console.quiet = False
            response = {
                "status": 401,
                "message": "Authenticated failed, please authenticate Safety and try again",
                "data": {},
            }
            console.print_json(json.dumps(response))
        else:
            console.print()
            console.print(
                "[red]Safety is not authenticated, please first authenticate and try again.[/red]"
            )
            console.print()
            console.print(
                "To authenticate, use the `auth` command: `safety auth login` Or for more help: `safety auth —help`"
            )
        sys.exit(1)

    if not data:
        raise SafetyException("No data found.")

    console.print("[green]Safety CLI is authenticated:[/green]")

    from rich.padding import Padding

    organization = data.get("organization", "-")
    account = data.get("user_email", "-")
    current_version = (
        f"Current version: {VERSION} (Python {PYTHON_VERSION} on {OS_TYPE})"
    )
    latest_available_version = data.get("safety_updates", {}).get("stable_version", "-")

    details = [
        f"Organization: {organization}",
        f"Account: {account}",
        current_version,
        f"Latest stable available version: {latest_available_version}",
    ]

    for msg in details:
        console.print(Padding(msg, (0, 0, 0, 1)), emoji=True)

    console.print()

    if latest_available_version:
        try:
            # Compare the current version and the latest available version using packaging.version
            if packaging_version.parse(
                latest_available_version
            ) > packaging_version.parse(VERSION):
                console.print(
                    f"Update available: Safety version {latest_available_version}"
                )
                console.print()
                console.print(
                    f"If Safety was installed from a requirements file, update Safety to version {latest_available_version} in that requirements file."
                )
                console.print()
                console.print(
                    f"Pip: To install the updated version of Safety directly via pip, run: pip install safety=={latest_available_version}"
                )
            elif packaging_version.parse(
                latest_available_version
            ) < packaging_version.parse(VERSION):
                # Notify user about downgrading
                console.print(
                    f"Latest stable version is {latest_available_version}. If you want to downgrade to this version, you can run: pip install safety=={latest_available_version}"
                )
            else:
                console.print(
                    "You are already using the latest stable version of Safety."
                )
        except InvalidVersion as invalid_version:
            LOG.exception(f"Invalid version format encountered: {invalid_version}")
            console.print(
                f"Error: Invalid version format encountered for the latest available version: {latest_available_version}"
            )
            console.print("Please report this issue or try again later.")

    if console.quiet:
        console.quiet = False
        response = {"status": 200, "message": "", "data": data}
        console.print_json(json.dumps(response))


cli.add_command(typer.main.get_command(cli_app), name="check-updates")
cli.add_command(typer.main.get_command(init_app), name="init")
cli.add_command(typer.main.get_command(scan_project_app), name="scan")
cli.add_command(typer.main.get_command(scan_system_app), name="system-scan")
cli.add_command(typer.main.get_command(codebase_app), name="codebase")

tool_commands.auto_register_tools(group=cli)

cli.add_command(typer.main.get_command(auth_app), name="auth")
cli.add_command(typer.main.get_command(firewall_app), name="firewall")

cli.add_command(alert)

if __name__ == "__main__":
    cli()
