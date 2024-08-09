# -*- coding: utf-8 -*-
from __future__ import absolute_import
import configparser
from dataclasses import asdict
from enum import Enum
import requests
import time

import json
import logging
import os
from pathlib import Path
import platform
import sys
from functools import wraps
from typing import Dict, Optional

import click
import typer

from safety import safety
from safety.console import main_console as console
from safety.alerts import alert
from safety.auth import auth, inject_session, proxy_options, auth_options
from safety.auth.models import Organization
from safety.scan.constants import CLI_LICENSES_COMMAND_HELP, CLI_MAIN_INTRODUCTION, CLI_DEBUG_HELP, CLI_DISABLE_OPTIONAL_TELEMETRY_DATA_HELP, \
    DEFAULT_EPILOG, DEFAULT_SPINNER, CLI_CHECK_COMMAND_HELP, CLI_CHECK_UPDATES_HELP, CLI_CONFIGURE_HELP, CLI_GENERATE_HELP, \
    CLI_CONFIGURE_PROXY_TIMEOUT, CLI_CONFIGURE_PROXY_REQUIRED, CLI_CONFIGURE_ORGANIZATION_ID, CLI_CONFIGURE_ORGANIZATION_NAME, \
    CLI_CONFIGURE_SAVE_TO_SYSTEM, CLI_CONFIGURE_PROXY_HOST_HELP, CLI_CONFIGURE_PROXY_PORT_HELP, CLI_CONFIGURE_PROXY_PROTOCOL_HELP, \
    CLI_GENERATE_PATH
from .cli_util import SafetyCLICommand, SafetyCLILegacyGroup, SafetyCLILegacyCommand, SafetyCLISubGroup, SafetyCLIUtilityCommand, handle_cmd_exception
from safety.constants import CONFIG_FILE_USER, CONFIG_FILE_SYSTEM, EXIT_CODE_VULNERABILITIES_FOUND, EXIT_CODE_OK, EXIT_CODE_FAILURE
from safety.errors import InvalidCredentialError, SafetyException, SafetyError
from safety.formatter import SafetyFormatter
from safety.models import SafetyCLI
from safety.output_utils import should_add_nl
from safety.safety import get_packages, read_vulnerabilities, process_fixes
from safety.util import get_packages_licenses, initializate_config_dirs, output_exception, \
    MutuallyExclusiveOption, DependentOption, transform_ignore, SafetyPolicyFile, active_color_if_needed, \
    get_processed_options, get_safety_version, json_alias, bare_alias, html_alias, SafetyContext, is_a_remote_mirror, \
    filter_announcements, get_fix_options
from safety.scan.command import scan_project_app, scan_system_app
from safety.auth.cli import auth_app
from safety_schemas.models import ConfigModel, Stage

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated

LOG = logging.getLogger(__name__)

def get_network_telemetry():
    import psutil
    import socket
    network_info = {}
    try:
        # Get network IO statistics
        net_io = psutil.net_io_counters()
        network_info['bytes_sent'] = net_io.bytes_sent
        network_info['bytes_recv'] = net_io.bytes_recv
        network_info['packets_sent'] = net_io.packets_sent
        network_info['packets_recv'] = net_io.packets_recv

        # Test network speed (download speed)
        test_url = "https://data.safetycli.com/api/v1/safety/announcements/"  # Test the download speed
        start_time = time.perf_counter()
        try:
            response = requests.get(test_url, timeout=10)
            end_time = time.perf_counter()
            download_time = end_time - start_time
            download_speed = len(response.content) / download_time
            network_info['download_speed'] = download_speed
        except requests.RequestException as e:
            network_info['download_speed'] = None
            network_info['error'] = str(e)


        # Get network addresses
        net_if_addrs = psutil.net_if_addrs()
        network_info['interfaces'] = {iface: [addr.address for addr in addrs if addr.family == socket.AF_INET] for iface, addrs in net_if_addrs.items()}

        # Get network connections
        net_connections = psutil.net_connections(kind='inet')
        network_info['connections'] = [
            {
                'fd': conn.fd,
                'family': conn.family,
                'type': conn.type,
                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}",
                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                'status': conn.status
            }
            for conn in net_connections
        ]

        # Get network interface stats
        net_if_stats = psutil.net_if_stats()
        network_info['interface_stats'] = {
            iface: {
                'isup': stats.isup,
                'duplex': stats.duplex,
                'speed': stats.speed,
                'mtu': stats.mtu
            }
            for iface, stats in net_if_stats.items()
        }
    except psutil.AccessDenied as e:
        network_info['error'] = f"Access denied when trying to gather network telemetry: {e}"

    return network_info

def preprocess_args(f):
    if '--debug' in sys.argv:
        index = sys.argv.index('--debug')
        if len(sys.argv) > index + 1:
            next_arg = sys.argv[index + 1]
            if next_arg in ('1', 'true'):
                sys.argv.pop(index + 1)  # Remove the next argument (1 or true)
    return f

def configure_logger(ctx, param, debug):
    level = logging.CRITICAL

    if debug:
        level = logging.DEBUG

    logging.basicConfig(format='%(asctime)s %(name)s => %(message)s', level=level)

    if debug:
        # Log the contents of the config.ini file
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE_USER)
        LOG.debug('Config file contents:')
        for section in config.sections():
            LOG.debug('[%s]', section)
            for key, value in config.items(section):
                LOG.debug('%s = %s', key, value)

        # Log the proxy settings if they were attempted
        if 'proxy' in config:
            LOG.debug('Proxy configuration attempted with settings: %s', dict(config['proxy']))

        # Collect and log network telemetry data
        network_telemetry = get_network_telemetry()
        LOG.debug('Network telemetry: %s', network_telemetry)

@click.group(cls=SafetyCLILegacyGroup, help=CLI_MAIN_INTRODUCTION, epilog=DEFAULT_EPILOG)
@auth_options()
@proxy_options
@click.option('--disable-optional-telemetry', default=False, is_flag=True, show_default=True, help=CLI_DISABLE_OPTIONAL_TELEMETRY_DATA_HELP)
@click.option('--debug', is_flag=True, help=CLI_DEBUG_HELP, callback=configure_logger)
@click.version_option(version=get_safety_version())
@click.pass_context
@inject_session
@preprocess_args
def cli(ctx, debug, disable_optional_telemetry):
    """
    Scan and secure Python projects against package vulnerabilities. To get started navigate to a Python project and run `safety scan`.
    """
    SafetyContext().safety_source = 'cli'
    telemetry = not disable_optional_telemetry
    ctx.obj.config = ConfigModel(telemetry_enabled=telemetry)
    level = logging.CRITICAL
    if debug:
        level = logging.DEBUG

    logging.basicConfig(format='%(asctime)s %(name)s => %(message)s', level=level)

    LOG.info(f'Telemetry enabled: {ctx.obj.config.telemetry_enabled}')

    # Before any command make sure that the parent dirs for Safety config are present.
    initializate_config_dirs()


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
        kwargs.pop('proxy_protocol', None)
        kwargs.pop('proxy_host', None)
        kwargs.pop('proxy_port', None)

        if ctx.get_parameter_source("json_version") != click.core.ParameterSource.DEFAULT and not (
                save_json or json or output == 'json'):
            raise click.UsageError(
                "Illegal usage: `--json-version` only works with JSON related outputs."
            )

        try:

            if ctx.get_parameter_source("apply_remediations") != click.core.ParameterSource.DEFAULT:
                if not authenticated:
                    raise InvalidCredentialError(message="The --apply-security-updates option needs authentication. See {link}.")
                if not files:
                    raise SafetyError(message='--apply-security-updates only works with files; use the "-r" option to '
                                              'specify files to remediate.')

            auto_remediation_limit = get_fix_options(policy_file, auto_remediation_limit)
            policy_file, server_audit_and_monitor = safety.get_server_policies(ctx.obj.auth.client, policy_file=policy_file,
                                                                               proxy_dictionary=None)
            audit_and_monitor = (audit_and_monitor and server_audit_and_monitor)

            kwargs.update({"auto_remediation_limit": auto_remediation_limit,
                           "policy_file":policy_file,
                           "audit_and_monitor": audit_and_monitor})

        except SafetyError as e:
            LOG.exception('Expected SafetyError happened: %s', e)
            output_exception(e, exit_code_output=exit_code)
        except Exception as e:
            LOG.exception('Unexpected Exception happened: %s', e)
            exception = e if isinstance(e, SafetyException) else SafetyException(info=e)
            output_exception(exception, exit_code_output=exit_code)

        return f(ctx, *args, **kwargs)

    return inner


@cli.command(cls=SafetyCLILegacyCommand, utility_command=True, help=CLI_CHECK_COMMAND_HELP)
@proxy_options
@auth_options(stage=False)
@click.option("--db", default="",
              help="Path to a local or remote vulnerability database. Default: empty")
@click.option("--full-report/--short-report", default=False, cls=MutuallyExclusiveOption,
              mutually_exclusive=["output", "json", "bare"],
              with_values={"output": ['json', 'bare'], "json": [True, False], "html": [True, False], "bare": [True, False]},
              help='Full reports include a security advisory (if available). Default: --short-report')
@click.option("--cache", is_flag=False, flag_value=60, default=0,
              help="Cache requests to the vulnerability database locally. Default: 0 seconds",
              hidden=True)
@click.option("--stdin", default=False, cls=MutuallyExclusiveOption, mutually_exclusive=["files"],
              help="Read input from stdin.", is_flag=True, show_default=True)
@click.option("files", "--file", "-r", multiple=True, type=click.File(), cls=MutuallyExclusiveOption,
              mutually_exclusive=["stdin"],
              help="Read input from one (or multiple) requirement files. Default: empty")
@click.option("--ignore", "-i", multiple=True, type=str, default=[], callback=transform_ignore,
              help="Ignore one (or multiple) vulnerabilities by ID (coma separated). Default: empty")
@click.option("ignore_unpinned_requirements", "--ignore-unpinned-requirements/--check-unpinned-requirements", "-iur",
              default=None, help="Check or ignore unpinned requirements found.")
@click.option('--json', default=False, cls=MutuallyExclusiveOption, mutually_exclusive=["output", "bare"],
              with_values={"output": ['screen', 'text', 'bare', 'json', 'html'], "bare": [True, False]}, callback=json_alias,
              hidden=True, is_flag=True, show_default=True)
@click.option('--html', default=False, cls=MutuallyExclusiveOption, mutually_exclusive=["output", "bare"],
              with_values={"output": ['screen', 'text', 'bare', 'json', 'html'], "bare": [True, False]}, callback=html_alias,
              hidden=True, is_flag=True, show_default=True)
@click.option('--bare', default=False, cls=MutuallyExclusiveOption, mutually_exclusive=["output", "json"],
              with_values={"output": ['screen', 'text', 'bare', 'json'], "json": [True, False]}, callback=bare_alias,
              hidden=True, is_flag=True, show_default=True)
@click.option('--output', "-o", type=click.Choice(['screen', 'text', 'json', 'bare', 'html'], case_sensitive=False),
              default='screen', callback=active_color_if_needed, envvar='SAFETY_OUTPUT')
@click.option("--exit-code/--continue-on-error", default=True,
              help="Output standard exit codes. Default: --exit-code")
@click.option("--policy-file", type=SafetyPolicyFile(), default='.safety-policy.yml',
              help="Define the policy file to be used")
@click.option("--audit-and-monitor/--disable-audit-and-monitor", default=True,
              help="Send results back to safetycli.com for viewing on your dashboard. Requires an API key.")
@click.option("project", "--project-id", "--project", default=None,
              help="Project to associate this scan with on safetycli.com. "
                   "Defaults to a canonicalized github style name if available, otherwise unknown")
@click.option("--save-json", default="", help="Path to where the output file will be placed; if the path is a"
                                              " directory, Safety will use safety-report.json as filename."
                                              " Default: empty")
@click.option("--save-html", default="", help="Path to where the output file will be placed; if the path is a"
                                              " directory, Safety will use safety-report.html as the main file. "
                                              "Default: empty")
@click.option("apply_remediations", "--apply-security-updates", "-asu", default=False, is_flag=True,
              help="Apply security updates in your requirement files.")
@click.option("auto_remediation_limit", "--auto-security-updates-limit", "-asul", multiple=True,
              type=click.Choice(['patch', 'minor', 'major']), default=['patch'],
              help="Define the limit to be used for automatic security updates in your requirement files."
                   " Default: patch")
@click.option("no_prompt", "--no-prompt", "-np", default=False, help="Safety won't ask for remediations outside of "
                                                                     "the remediation limit.", is_flag=True,
              show_default=True)
@click.option('json_version', '--json-output-format', type=click.Choice(['0.5', '1.1']), default="1.1",
              help="Select the JSON version to be used in the output", show_default=True)
@click.pass_context
@clean_check_command
def check(ctx, db, full_report, stdin, files, cache, ignore, ignore_unpinned_requirements, output, json,
          html, bare, exit_code, policy_file, audit_and_monitor, project,
          save_json, save_html, apply_remediations,
          auto_remediation_limit, no_prompt, json_version):
    """
    [underline][DEPRECATED][/underline] `check` has been replaced by the `scan` command, and will be unsupported beyond 1 May 2024.Find vulnerabilities at a target file or enviroment.
    """
    LOG.info('Running check command')

    non_interactive = (not sys.stdout.isatty() and os.environ.get("SAFETY_OS_DESCRIPTION", None) != 'run')
    silent_outputs = ['json', 'bare', 'html']
    is_silent_output = output in silent_outputs
    prompt_mode = bool(not non_interactive and not stdin and not is_silent_output) and not no_prompt
    kwargs = {'version': json_version} if output == 'json' else {}

    try:
        packages = get_packages(files, stdin)

        ignore_severity_rules = None
        ignore, ignore_severity_rules, exit_code, ignore_unpinned_requirements, project = \
            get_processed_options(policy_file, ignore, ignore_severity_rules, exit_code, ignore_unpinned_requirements,
                                  project)
        is_env_scan = not stdin and not files

        params = {'stdin': stdin, 'files': files, 'policy_file': policy_file, 'continue_on_error': not exit_code,
                  'ignore_severity_rules': ignore_severity_rules, 'project': project,
                  'audit_and_monitor': audit_and_monitor, 'prompt_mode': prompt_mode,
                  'auto_remediation_limit': auto_remediation_limit,
                  'apply_remediations': apply_remediations,
                  'ignore_unpinned_requirements': ignore_unpinned_requirements}

        LOG.info('Calling the check function')
        vulns, db_full = safety.check(session=ctx.obj.auth.client, packages=packages, db_mirror=db, cached=cache, ignore_vulns=ignore,
                                      ignore_severity_rules=ignore_severity_rules, proxy=None,
                                      include_ignored=True, is_env_scan=is_env_scan, telemetry=ctx.obj.config.telemetry_enabled,
                                      params=params)
        LOG.debug('Vulnerabilities returned: %s', vulns)
        LOG.debug('full database returned is None: %s', db_full is None)

        LOG.info('Safety is going to calculate remediations')

        remediations = safety.calculate_remediations(vulns, db_full)

        announcements = []
        if not db or is_a_remote_mirror(db):
            LOG.info('Not local DB used, Getting announcements')
            announcements = safety.get_announcements(ctx.obj.auth.client, telemetry=ctx.obj.config.telemetry_enabled)

        announcements.extend(safety.add_local_notifications(packages, ignore_unpinned_requirements))

        LOG.info('Safety is going to render the vulnerabilities report using %s output', output)

        fixes = []

        if apply_remediations and is_silent_output:
            # it runs and apply only automatic fixes.
            fixes = process_fixes(files, remediations, auto_remediation_limit, output, no_output=True,
                                  prompt=False)

        output_report = SafetyFormatter(output, **kwargs).render_vulnerabilities(announcements, vulns, remediations,
                                                                                 full_report, packages, fixes)

        # Announcements are send to stderr if not terminal, it doesn't depend on "exit_code" value
        stderr_announcements = filter_announcements(announcements=announcements, by_type='error')
        if stderr_announcements and non_interactive:
            LOG.info('sys.stdout is not a tty, error announcements are going to be send to stderr')
            click.secho(SafetyFormatter(output='text').render_announcements(stderr_announcements), fg="red",
                        file=sys.stderr)

        found_vulns = list(filter(lambda v: not v.ignored, vulns))
        LOG.info('Vulnerabilities found (Not ignored): %s', len(found_vulns))
        LOG.info('All vulnerabilities found (ignored and Not ignored): %s', len(vulns))

        click.secho(output_report, nl=should_add_nl(output, found_vulns), file=sys.stdout)

        post_processing_report = (save_json or audit_and_monitor or apply_remediations)

        if post_processing_report:
            if apply_remediations and not is_silent_output:
                # prompt_mode fixing after main check output if prompt is enabled.
                fixes = process_fixes(files, remediations, auto_remediation_limit, output, no_output=False,
                                      prompt=prompt_mode)

            # Render fixes
            json_report = output_report if output == 'json' else \
                SafetyFormatter(output='json', version=json_version).render_vulnerabilities(announcements, vulns,
                                                                                            remediations, full_report,
                                                                                            packages, fixes)

            safety.save_report(save_json, 'safety-report.json', json_report)

        if save_html:
            html_report = output_report if output == 'html' else SafetyFormatter(output='html').render_vulnerabilities(
                announcements, vulns, remediations, full_report, packages, fixes)

            safety.save_report(save_html, 'safety-report.html', html_report)

        if exit_code and found_vulns:
            LOG.info('Exiting with default code for vulnerabilities found')
            sys.exit(EXIT_CODE_VULNERABILITIES_FOUND)

        sys.exit(EXIT_CODE_OK)

    except SafetyError as e:
        LOG.exception('Expected SafetyError happened: %s', e)
        output_exception(e, exit_code_output=exit_code)
    except Exception as e:
        LOG.exception('Unexpected Exception happened: %s', e)
        exception = e if isinstance(e, SafetyException) else SafetyException(info=e)
        output_exception(exception, exit_code_output=exit_code)


def clean_license_command(f):
    """
    Main entry point for validation.
    """
    @wraps(f)
    def inner(ctx, *args, **kwargs):
        # TODO: Remove this soon, for now it keeps a legacy behavior
        kwargs.pop("key", None)
        kwargs.pop('proxy_protocol', None)
        kwargs.pop('proxy_host', None)
        kwargs.pop('proxy_port', None)

        return f(ctx, *args, **kwargs)

    return inner


@cli.command(cls=SafetyCLILegacyCommand, utility_command=True, help=CLI_LICENSES_COMMAND_HELP)
@proxy_options
@auth_options(stage=False)
@click.option("--db", default="",
              help="Path to a local license database. Default: empty")
@click.option('--output', "-o", type=click.Choice(['screen', 'text', 'json', 'bare'], case_sensitive=False),
              default='screen')
@click.option("--cache", default=0,
              help='Whether license database file should be cached.'
                   'Default: 0 seconds')
@click.option("files", "--file", "-r", multiple=True, type=click.File(),
              help="Read input from one (or multiple) requirement files. Default: empty")
@click.pass_context
@clean_license_command
def license(ctx, db, output, cache, files):
    """
    Find the open source licenses used by your Python dependencies.
    """
    LOG.info('Running license command')
    packages = get_packages(files, False)
    licenses_db = {}

    SafetyContext().params = ctx.params

    try:
        licenses_db = safety.get_licenses(session=ctx.obj.auth.client, db_mirror=db, cached=cache,
                                          telemetry=ctx.obj.config.telemetry_enabled)
    except SafetyError as e:
        LOG.exception('Expected SafetyError happened: %s', e)
        output_exception(e, exit_code_output=False)
    except Exception as e:
        LOG.exception('Unexpected Exception happened: %s', e)
        exception = e if isinstance(e, SafetyException) else SafetyException(info=e)
        output_exception(exception, exit_code_output=False)

    filtered_packages_licenses = get_packages_licenses(packages=packages, licenses_db=licenses_db)

    announcements = []
    if not db:
        announcements = safety.get_announcements(session=ctx.obj.auth.client, telemetry=ctx.obj.config.telemetry_enabled)

    output_report = SafetyFormatter(output=output).render_licenses(announcements, filtered_packages_licenses)

    click.secho(output_report, nl=True)


@cli.command(cls=SafetyCLILegacyCommand, utility_command=True, help=CLI_GENERATE_HELP)
@click.option("--path", default=".", help=CLI_GENERATE_PATH)
@click.argument('name', required=True)
@click.pass_context
def generate(ctx, name, path):
    """Create a boilerplate Safety CLI policy file

    NAME is the name of the file type to generate. Valid values are: policy_file
    """
    if name != 'policy_file':
        click.secho(f'This Safety version only supports "policy_file" generation. "{name}" is not supported.', fg='red',
                    file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)

    LOG.info('Running generate %s', name)

    path = Path(path)
    if not path.exists():
        click.secho(f'The path "{path}" does not exist.', fg='red',
                    file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)

    policy = path / '.safety-policy.yml'

    default_config = ConfigModel()

    try:
        default_config.save_policy_file(policy)
        LOG.debug('Safety created the policy file.')
        msg = f'A default Safety policy file has been generated! Review the file contents in the path {path} in the ' \
               'file: .safety-policy.yml'
        click.secho(msg, fg='green')
    except Exception as exc:
        if isinstance(exc, OSError):
            LOG.debug('Unable to generate %s because: %s', name, exc.errno)

        click.secho(f'{str(exc)} error.', fg='red',
                    file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)


@cli.command(cls=SafetyCLILegacyCommand, utility_command=True)
@click.option("--path", default=".safety-policy.yml", help="Path where the generated file will be saved. Default: current directory")
@click.argument('name')
@click.argument('version', required=False)
@click.pass_context
def validate(ctx, name, version, path):
    """Verify that a local policy file is valid

    NAME is the name of the file type to validate. Valid values are: policy_file
    """
    if name != 'policy_file':
        click.secho(f'This Safety version only supports "policy_file" validation. "{name}" is not supported.', fg='red',
                    file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)

    LOG.info('Running validate %s', name)

    if not os.path.exists(path):
        click.secho(f'The path "{path}" does not exist.', fg='red', file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)

    if version not in ["3.0", "2.0", None]:
        click.secho(f'Version "{version}" is not a valid value, allowed values are 3.0 and 2.0. Use --path to specify the target file.', fg='red', file=sys.stderr)
        sys.exit(EXIT_CODE_FAILURE)

    def fail_validation(e):
        click.secho(str(e).lstrip(), fg='red', file=sys.stderr)
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

        click.secho(f"The Safety policy ({version}) file " \
                    "(Used for scan and system-scan commands) " \
                    "was successfully parsed " \
                    "with the following values:", fg="green")
        if policy and policy.config:
            result = policy.config.as_v30().json()
    else:
        try:
            values = SafetyPolicyFile().convert(path, None, None)
        except Exception as e:
            click.secho(str(e).lstrip(), fg='red', file=sys.stderr)
            sys.exit(EXIT_CODE_FAILURE)

        del values['raw']

        result = json.dumps(values, indent=4, default=str)

        click.secho("The Safety policy file " \
                    "(Valid only for the check command) " \
                    "was successfully parsed with the " \
                    "following values:", fg="green")

    console.print_json(result)


@cli.command(cls=SafetyCLILegacyCommand,
             help=CLI_CONFIGURE_HELP,
             utility_command=True)
@click.option("--proxy-protocol", "-pr", type=click.Choice(['http', 'https']), default='https', cls=DependentOption,
              required_options=['proxy_host'],
              help=CLI_CONFIGURE_PROXY_PROTOCOL_HELP)
@click.option("--proxy-host", "-ph", multiple=False, type=str, default=None,
              help=CLI_CONFIGURE_PROXY_HOST_HELP)
@click.option("--proxy-port", "-pp", multiple=False, type=int, default=80,
              cls=DependentOption,
              required_options=['proxy_host'],
              help=CLI_CONFIGURE_PROXY_PORT_HELP)
@click.option("--proxy-timeout", "-pt", multiple=False, type=int, default=None,
              help=CLI_CONFIGURE_PROXY_TIMEOUT)
@click.option('--proxy-required', default=False,
              help=CLI_CONFIGURE_PROXY_REQUIRED)
@click.option("--organization-id", "-org-id", multiple=False, default=None,
              cls=DependentOption,
              required_options=['organization_name'],
              help=CLI_CONFIGURE_ORGANIZATION_ID)
@click.option("--organization-name", "-org-name", multiple=False, default=None,
              cls=DependentOption,
              required_options=['organization_id'],
              help=CLI_CONFIGURE_ORGANIZATION_NAME)
@click.option("--stage", "-stg", multiple=False, default=Stage.development.value,
              type=click.Choice([stage.value for stage in Stage]),
              help="The project development stage to be tied to the current device.")
@click.option("--save-to-system/--save-to-user", default=False, is_flag=True,
              help=CLI_CONFIGURE_SAVE_TO_SYSTEM)
@click.pass_context
def configure(ctx, proxy_protocol, proxy_host, proxy_port, proxy_timeout,
              proxy_required, organization_id, organization_name, stage,
              save_to_system):
    """
    Configure global settings, like proxy settings and organization details
    """

    config = configparser.ConfigParser()
    if save_to_system:
        if not CONFIG_FILE_SYSTEM:
            click.secho(
                f"Unable to determine the system wide config path. You can set the SAFETY_SYSTEM_CONFIG_PATH env var")
            sys.exit(1)

        CONFIG_FILE = CONFIG_FILE_SYSTEM
    else:
        CONFIG_FILE = CONFIG_FILE_USER

    config.read(CONFIG_FILE)

    PROXY_SECTION_NAME: str = 'proxy'
    PROXY_TIMEOUT_KEY: str = 'timeout'
    PROXY_REQUIRED_KEY: str = 'required'

    if organization_id:
        config['organization'] = asdict(Organization(id=organization_id,
                                                     name=organization_name))

    DEFAULT_PROXY_TIMEOUT: int = 500

    if not proxy_timeout:
        try:
            proxy_timeout = int(config['proxy']['timeout'])
        except Exception:
            proxy_timeout = DEFAULT_PROXY_TIMEOUT

    new_proxy_config = {}
    new_proxy_config.setdefault(PROXY_TIMEOUT_KEY, str(proxy_timeout))
    new_proxy_config.setdefault(PROXY_REQUIRED_KEY, str(proxy_required))

    if proxy_host:
        new_proxy_config.update({
            'protocol': proxy_protocol,
            'host': proxy_host,
            'port': str(proxy_port)
        })

    if not config.has_section(PROXY_SECTION_NAME):
        config.add_section(PROXY_SECTION_NAME)

    proxy_config = dict(config.items(PROXY_SECTION_NAME))
    proxy_config.update(new_proxy_config)

    for key, value in proxy_config.items():
        config.set(PROXY_SECTION_NAME, key, value)

    if stage:
        config['host'] = {'stage': "development" if stage == "dev" else stage}

    try:
        with open(CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
    except Exception as e:
        if (isinstance(e, OSError) and e.errno == 2 or e is PermissionError) and save_to_system:
            click.secho("Unable to save the configuration: writing to system-wide Safety configuration file requires admin privileges")
        else:
            click.secho(f"Unable to save the configuration, error: {e}")
        sys.exit(1)


cli_app = typer.Typer(rich_markup_mode="rich", cls=SafetyCLISubGroup)
typer.rich_utils.STYLE_HELPTEXT = ""

def print_check_updates_header(console):
    VERSION = get_safety_version()
    console.print(
        f"Safety {VERSION} checking for Safety version and configuration updates:")

class Output(str, Enum):
    SCREEN = "screen"
    JSON = "json"

@cli_app.command(
        cls=SafetyCLIUtilityCommand,
        help=CLI_CHECK_UPDATES_HELP,
        name="check-updates", epilog=DEFAULT_EPILOG,
        context_settings={"allow_extra_args": True,
                          "ignore_unknown_options": True},
                          )
@handle_cmd_exception
def check_updates(ctx: typer.Context,
         version: Annotated[
             int,
             typer.Option(min=1),
         ] = 1,
         output: Annotated[Output,
                         typer.Option(
                            help="The main output generated by Safety CLI.")
                         ] = Output.SCREEN):
    """
    Check for Safety CLI version updates
    """

    if output is Output.JSON:
        console.quiet = True

    print_check_updates_header(console)

    wait_msg = "Authenticating and checking for Safety CLI updates"

    VERSION = get_safety_version()
    PYTHON_VERSION = platform.python_version()
    OS_TYPE = platform.system()

    authenticated = ctx.obj.auth.client.is_using_auth_credentials()
    data = None

    console.print()
    with console.status(wait_msg, spinner=DEFAULT_SPINNER):
        try:
            data = ctx.obj.auth.client.check_updates(version=1,
                                                     safety_version=VERSION,
                                                     python_version=PYTHON_VERSION,
                                                     os_type=OS_TYPE,
                                                     os_release=platform.release(),
                                                     os_description=platform.platform())
        except InvalidCredentialError as e:
            authenticated = False
        except Exception as e:
            LOG.exception(f'Failed to check updates, reason: {e}')
            raise e

    if not authenticated:
        if console.quiet:
            console.quiet = False
            response = {
                "status": 401,
                "message": "Authenticated failed, please authenticate Safety and try again",
                "data": {}
            }
            console.print_json(json.dumps(response))
        else:
            console.print()
            console.print("[red]Safety is not authenticated, please first authenticate and try again.[/red]")
            console.print()
            console.print("To authenticate, use the `auth` command: `safety auth login` Or for more help: `safety auth —help`")
        sys.exit(1)

    if not data:
        raise SafetyException("No data found.")

    console.print("[green]Safety CLI is authenticated:[/green]")

    from rich.padding import Padding
    organization = data.get("organization", "-")
    account = data.get("user_email", "-")
    current_version = f"Current version: {VERSION} (Python {PYTHON_VERSION} on {OS_TYPE})"
    latest_available_version = data.get("safety_updates", {}).get("stable_version", "-")

    details = [f"Organization: {organization}",
               f"Account: {account}",
               current_version,
               f"Latest available version: {latest_available_version}"
               ]

    for msg in details:
        console.print(Padding(msg, (0, 0, 0, 1)), emoji=True)

    console.print()

    if latest_available_version:
        console.print(f"Update available: Safety version {latest_available_version}")
        console.print()
        console.print(
            f"If Safety was installed from a requirements file, update Safety to version {latest_available_version} in that requirements file."
        )
        console.print()
        # `pip -i <source_url> install safety=={latest_available_version}` OR
        console.print(f"Pip: To install the updated version of Safety directly via pip, run: `pip install safety=={latest_available_version}`")

    if console.quiet:
        console.quiet = False
        response = {
            "status": 200,
            "message": "",
            "data": data
        }
        console.print_json(json.dumps(response))


cli.add_command(typer.main.get_command(cli_app), "check-updates")
cli.add_command(typer.main.get_command(scan_project_app), "scan")
cli.add_command(typer.main.get_command(scan_system_app), "system-scan")

cli.add_command(typer.main.get_command(auth_app), "auth")

cli.add_command(alert)

if __name__ == "__main__":
    cli()
