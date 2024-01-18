import logging
import sys
import json
from typing import Any
import click

from dataclasses import dataclass

from safety.cli_util import SafetyCLILegacyGroup

from . import github
from safety.util import SafetyPolicyFile
from safety.scan.constants import CLI_ALERT_COMMAND_HELP

LOG = logging.getLogger(__name__)

@dataclass
class Alert:
    report: Any
    key: str
    policy: Any = None
    requirements_files: Any = None

@click.group(cls=SafetyCLILegacyGroup, help=CLI_ALERT_COMMAND_HELP, deprecated=True, utility_command=True)
@click.option('--check-report', help='JSON output of Safety Check to work with.', type=click.File('r'), default=sys.stdin, required=True)
@click.option("--key", envvar="SAFETY_API_KEY",
              help="API Key for safetycli.com's vulnerability database. Can be set as SAFETY_API_KEY "
                   "environment variable.", required=True)
@click.option("--policy-file", type=SafetyPolicyFile(), default='.safety-policy.yml',
              help="Define the policy file to be used")
@click.pass_context
def alert(ctx, check_report, policy_file, key):
    LOG.info('alert started')
    LOG.info(f'check_report is using stdin: {check_report == sys.stdin}')

    with check_report:
        # TODO: This breaks --help for subcommands
        try:
            safety_report = json.load(check_report)
        except json.decoder.JSONDecodeError as e:
            LOG.info('Error in the JSON report.')
            click.secho("Error decoding input JSON: {}".format(e.msg), fg='red')
            sys.exit(1)

    if not 'report_meta' in safety_report:
        click.secho("You must pass in a valid Safety Check JSON report", fg='red')
        sys.exit(1)

    ctx.obj = Alert(report=safety_report, policy=policy_file if policy_file else {}, key=key)

alert.add_command(github.github_pr)
alert.add_command(github.github_issue)
