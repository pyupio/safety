from functools import wraps
import logging
import os
from pathlib import Path
from typing import Any, List, Optional

from rich.padding import Padding
from safety_schemas.models import ConfigModel, ProjectModel
from rich.console import Console
from safety.auth.cli import render_email_note
from safety.cli_util import process_auth_status_not_ready
from safety.console import main_console
from safety.constants import SYSTEM_POLICY_FILE, USER_POLICY_FILE
from safety.errors import SafetyError, SafetyException
from safety.scan.constants import DEFAULT_SPINNER
from safety.scan.main import download_policy, load_policy_file, resolve_policy
from safety.scan.models import ScanOutput, SystemScanOutput
from safety.scan.render import print_announcements, print_header, print_wait_policy_download
from safety.scan.util import GIT
from ..init.main import load_unverified_project_from_config, verify_project

from safety.scan.validators import fail_if_not_allowed_stage

from safety.util import build_telemetry_data, pluralize
from safety_schemas.models import MetadataModel, ScanType, ReportSchemaVersion, \
    PolicySource

LOG = logging.getLogger(__name__)


def scan_project_command_init(func):
    """
    Decorator to make general verifications before each project scan command.
    """
    @wraps(func)
    def inner(ctx, policy_file_path: Optional[Path], target: Path,
              output: ScanOutput,
              console: Console = main_console,
              *args, **kwargs):
        ctx.obj.console = console
        ctx.params.pop("console", None)

        if output.is_silent():
            console.quiet = True

        if not ctx.obj.auth.is_valid():
            process_auth_status_not_ready(console=console,
                                        auth=ctx.obj.auth, ctx=ctx)

        upload_request_id = kwargs.pop("upload_request_id", None)

        # Load .safety-project.ini
        unverified_project = load_unverified_project_from_config(project_root=target)

        print_header(console=console, targets=[target])

        stage = ctx.obj.auth.stage
        session = ctx.obj.auth.client
        git_data = GIT(root=target).build_git_data()
        origin = None
        branch = None

        if git_data:
            origin = git_data.origin
            branch = git_data.branch

        if ctx.obj.platform_enabled:
            verify_project(console, ctx, session, unverified_project, stage, origin)
        else:
            ctx.obj.project = ProjectModel(
                id="",
                name="Undefined project",
                project_path=unverified_project.project_path
            )

        ctx.obj.project.git = git_data
        ctx.obj.project.upload_request_id = upload_request_id

        if not policy_file_path:
            policy_file_path = target / Path(".safety-policy.yml")

        # Load Policy file and pull it from CLOUD
        local_policy = kwargs.pop("local_policy",
                                  load_policy_file(policy_file_path))

        cloud_policy = None
        if ctx.obj.platform_enabled:
            cloud_policy = print_wait_policy_download(console, (download_policy,
                                            {"session": session,
                                            "project_id": ctx.obj.project.id,
                                            "stage": stage,
                                            "branch": branch}))

        ctx.obj.project.policy = resolve_policy(local_policy, cloud_policy)
        config = ctx.obj.project.policy.config \
            if ctx.obj.project.policy and ctx.obj.project.policy.config \
                else ConfigModel()

        # Preserve global telemetry preference.
        if ctx.obj.config:
            if ctx.obj.config.telemetry_enabled is not None:
                config.telemetry_enabled = ctx.obj.config.telemetry_enabled

        ctx.obj.config = config

        console.print()

        if ctx.obj.auth.org and ctx.obj.auth.org.name:
            console.print(f"[bold]Organization[/bold]: {ctx.obj.auth.org.name}")

        # Check if an API key is set
        if ctx.obj.auth.client.get_authentication_type() == "api_key":
            details = {"Account": f"API key used"}
        else:

            if ctx.obj.auth.client.get_authentication_type() == "token":
                content = ctx.obj.auth.email
                if ctx.obj.auth.name != ctx.obj.auth.email:
                    content = f"{ctx.obj.auth.name}, {ctx.obj.auth.email}"

                details = {"Account": f"{content} {render_email_note(ctx.obj.auth)}"}
            else:
                details = {"Account": f"Offline - {os.getenv('SAFETY_DB_DIR')}"}

        if ctx.obj.project.id:
            details["Project"] = ctx.obj.project.id

        if ctx.obj.project.git:
            details[" Git branch"] = ctx.obj.project.git.branch

        details[" Environment"] = ctx.obj.auth.stage

        msg = "None, using Safety CLI default policies"

        if ctx.obj.project.policy:
            if ctx.obj.project.policy.source is PolicySource.cloud:
                msg = f"fetched from Safety Platform, " \
                    "ignoring any local Safety CLI policy files"
            else:
                if ctx.obj.project.id:
                    msg = f"local {ctx.obj.project.id} project scan policy"
                else:
                    msg = f"local scan policy file"

        details[" Scan policy"] = msg

        for k,v in details.items():
            console.print(f"[scan_meta_title]{k}[/scan_meta_title]: {v}")

        print_announcements(console=console, ctx=ctx)

        console.print()

        result = func(ctx, target=target, output=output, *args, **kwargs)


        return result

    return inner


def scan_system_command_init(func):
    """
    Decorator to make general verifications before each system scan command.
    """
    @wraps(func)
    def inner(ctx, policy_file_path: Optional[Path], targets: List[Path],
              output: SystemScanOutput,
              console: Console = main_console, *args, **kwargs):
        ctx.obj.console = console
        ctx.params.pop("console", None)

        if output.is_silent():
            console.quiet = True

        if not ctx.obj.auth.is_valid():
            process_auth_status_not_ready(console=console,
                                        auth=ctx.obj.auth, ctx=ctx)

        console.print()
        print_header(console=console, targets=targets, is_system_scan=True)

        if not policy_file_path:
            if SYSTEM_POLICY_FILE.exists():
                policy_file_path = SYSTEM_POLICY_FILE
            elif USER_POLICY_FILE.exists():
                policy_file_path = USER_POLICY_FILE

        # Load Policy file
        ctx.obj.system_scan_policy = load_policy_file(policy_file_path) if policy_file_path else None
        config = ctx.obj.system_scan_policy.config \
            if ctx.obj.system_scan_policy and ctx.obj.system_scan_policy.config \
                else ConfigModel()

        # Preserve global telemetry preference.
        if ctx.obj.config:
            if ctx.obj.config.telemetry_enabled is not None:
                config.telemetry_enabled = ctx.obj.config.telemetry_enabled

        ctx.obj.config = config

        if not any(targets):
            if any(config.scan.system_targets):
                targets = [Path(t).expanduser().absolute() for t in config.scan.system_targets]
            else:
                targets = [Path("/")]

            ctx.obj.metadata.scan_locations = targets

        console.print()

        if ctx.obj.auth.org and ctx.obj.auth.org.name:
            console.print(f"[bold]Organization[/bold]: {ctx.obj.auth.org.name}")

        details = {"Account": f"{ctx.obj.auth.name}, {ctx.obj.auth.email}",
                "Scan stage": ctx.obj.auth.stage}

        if ctx.obj.system_scan_policy:
            if ctx.obj.system_scan_policy.source is PolicySource.cloud:
                policy_type = "remote"
            else:
                policy_type = f'local ("{ctx.obj.system_scan_policy.id}")'

            org_name = " "
            if ctx.obj.auth.org and ctx.obj.auth.org.name:
                org_name = f" {ctx.obj.auth.org.name} "

            details["System scan policy"] = f"{policy_type}{org_name}organization policy:"

        for k,v in details.items():
            console.print(f"[bold]{k}[/bold]: {v}")

        if ctx.obj.system_scan_policy:

            dirs = [ign for ign in ctx.obj.config.scan.ignore if Path(ign).is_dir()]

            policy_details = [
                f"-> scanning from root {', '.join([str(t) for t in targets])} to a max folder depth of {ctx.obj.config.scan.max_depth}",
                f"-> excluding {len(dirs)} {pluralize('directory', len(dirs))} and their sub-directories",
                "-> target ecosystems: Python"
            ]
            for policy_detail in policy_details:
                console.print(
                    Padding(policy_detail,
                            (0, 0, 0, 1)), emoji=True)

        print_announcements(console=console, ctx=ctx)

        console.print()

        kwargs.update({"targets": targets})
        result = func(ctx, *args, **kwargs)
        return result

    return inner


def inject_metadata(func):
    """
    Build metadata per subcommand. A system scan can trigger a project scan,
    the project scan will need to build its own metadata.
    """
    @wraps(func)
    def inner(ctx, *args, **kwargs):
        telemetry = build_telemetry_data(telemetry=ctx.obj.config.telemetry_enabled,
                                         command=ctx.command.name,
                                         subcommand=ctx.invoked_subcommand)

        auth_type = ctx.obj.auth.client.get_authentication_type()

        scan_type = ScanType(ctx.command.name)
        target = kwargs.get("target", None)
        targets = kwargs.get("targets", None)

        if not scan_type:
            raise SafetyException("Missing scan_type.")

        if scan_type is ScanType.scan:
            if not target:
                raise SafetyException("Missing target.")
            targets = [target]

        metadata = MetadataModel(
            scan_type=scan_type,
            stage=ctx.obj.auth.stage,
            scan_locations=targets,
            authenticated=ctx.obj.auth.client.is_using_auth_credentials(),
            authentication_type=auth_type,
            telemetry=telemetry,
            schema_version=ReportSchemaVersion.v3_0
            )

        ctx.obj.schema = ReportSchemaVersion.v3_0
        ctx.obj.metadata = metadata
        ctx.obj.telemetry = telemetry

        return func(ctx, *args, **kwargs)

    return inner
