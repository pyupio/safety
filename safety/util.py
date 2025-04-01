import logging
import os
import platform
import re
import sys
from collections import defaultdict
from datetime import datetime
from difflib import SequenceMatcher
from threading import Lock
from typing import TYPE_CHECKING, Any, Dict, Generator, List, Optional, Tuple, Union

import click
from click import BadParameter
from dparse import filetypes, parse
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import parse as parse_version
from requests import PreparedRequest
from ruamel.yaml import YAML
from ruamel.yaml.error import MarkedYAMLError
from safety_schemas.models import TelemetryModel

from safety.constants import (
    HASH_REGEX_GROUPS,
    SYSTEM_CONFIG_DIR,
    USER_CONFIG_DIR,
)
from safety.errors import InvalidProvidedReportError
from safety.events.event_bus import start_event_bus
from safety.models import (
    Package,
    RequirementFile,
    SafetyRequirement,
    is_pinned_requirement,
)


if TYPE_CHECKING:
    from safety.cli_util import CustomContext
    from safety.models import SafetyCLI
    from safety.auth.models import Auth
    from safety.auth.utils import SafetyAuthSession

    import typer


LOG = logging.getLogger(__name__)


def is_a_remote_mirror(mirror: str) -> bool:
    """
    Check if a mirror URL is remote.

    Args:
        mirror (str): The mirror URL.

    Returns:
        bool: True if the mirror URL is remote, False otherwise.
    """
    return mirror.startswith("http://") or mirror.startswith("https://")


def is_supported_by_parser(path: str) -> bool:
    """
    Check if the file path is supported by the parser.

    Args:
        path (str): The file path.

    Returns:
        bool: True if the file path is supported, False otherwise.
    """
    supported_types = (
        ".txt",
        ".in",
        ".yml",
        ".ini",
        "Pipfile",
        "Pipfile.lock",
        "setup.cfg",
        "poetry.lock",
    )
    return path.endswith(supported_types)


def parse_requirement(dep: Any, found: Optional[str]) -> SafetyRequirement:
    """
    Parse a requirement.

    Args:
        dep (Any): The dependency.
        found (str): The location where the dependency was found.

    Returns:
        SafetyRequirement: The parsed requirement.
    """
    req = SafetyRequirement(dep)
    req.found = found

    if req.specifier == SpecifierSet(""):
        req.specifier = SpecifierSet(">=0")

    return req


def find_version(requirements: List[SafetyRequirement]) -> Optional[str]:
    """
    Find the version of a requirement.

    Args:
        requirements (List[SafetyRequirement]): The list of requirements.

    Returns:
        Optional[str]: The version if found, None otherwise.
    """
    ver = None

    if len(requirements) != 1:
        return ver

    specs = requirements[0].specifier

    if is_pinned_requirement(specs):
        ver = next(iter(requirements[0].specifier)).version

    return ver


def read_requirements(fh: Any, resolve: bool = True) -> Generator[Package, None, None]:  # type: ignore
    """
    Reads requirements from a file-like object and (optionally) from referenced files.

    Args:
        fh (Any): The file-like object to read from.
        resolve (bool): Resolves referenced files.

    Returns:
        Generator: Yields Package objects.
    """
    is_temp_file = not hasattr(fh, "name")
    path = None
    found = "temp_file"
    file_type = filetypes.requirements_txt
    absolute_path: Optional[str] = None

    if not is_temp_file and is_supported_by_parser(fh.name):
        LOG.debug("not temp and a compatible file")
        path = fh.name
        absolute_path = os.path.abspath(path)
        SafetyContext().scanned_full_path.append(absolute_path)
        found = path
        file_type = None

    LOG.debug(f"Path: {path}")
    LOG.debug(f"File Type: {file_type}")
    LOG.debug("Trying to parse file using dparse...")
    content = fh.read()
    LOG.debug(f"Content: {content}")
    dependency_file = parse(content, path=path, resolve=resolve, file_type=file_type)
    LOG.debug(f"Dependency file: {dependency_file.serialize()}")
    LOG.debug(
        f"Parsed, dependencies: {[dep.serialize() for dep in dependency_file.resolved_dependencies]}"
    )

    reqs_pkg = defaultdict(list)

    for req in dependency_file.resolved_dependencies:
        reqs_pkg[canonicalize_name(req.name)].append(req)

    for pkg, reqs in reqs_pkg.items():
        requirements = list(
            map(lambda req: parse_requirement(req, absolute_path), reqs)
        )
        version = find_version(requirements)

        yield Package(
            name=pkg,
            version=version,
            requirements=requirements,
            found=found,
            absolute_path=absolute_path,
            insecure_versions=[],
            secure_versions=[],
            latest_version=None,
            latest_version_without_known_vulnerabilities=None,
            more_info_url=None,
        )


def get_proxy_dict(
    proxy_protocol: str, proxy_host: str, proxy_port: int
) -> Optional[Dict[str, str]]:
    """
    Get the proxy dictionary for requests.

    Args:
        proxy_protocol (str): The proxy protocol.
        proxy_host (str): The proxy host.
        proxy_port (int): The proxy port.

    Returns:
        Optional[Dict[str, str]]: The proxy dictionary if all parameters are provided, None otherwise.
    """
    if proxy_protocol and proxy_host and proxy_port:
        # Safety only uses https request, so only https dict will be passed to requests
        return {"https": f"{proxy_protocol}://{proxy_host}:{str(proxy_port)}"}
    return None


def get_license_name_by_id(license_id: int, db: Dict[str, Any]) -> Optional[str]:
    """
    Get the license name by its ID.

    Args:
        license_id (int): The license ID.
        db (Dict[str, Any]): The database containing license information.

    Returns:
        Optional[str]: The license name if found, None otherwise.
    """
    licenses = db.get("licenses", [])
    for name, id in licenses.items():
        if id == license_id:
            return name
    return None


def get_flags_from_context() -> Dict[str, str]:
    """
    Get the flags from the current click context.

    Returns:
        Dict[str, str]: A dictionary of flags and their corresponding option names.
    """
    flags = {}
    context = click.get_current_context(silent=True)

    if context:
        for option in context.command.params:
            flags_per_opt = option.opts + option.secondary_opts
            for flag in flags_per_opt:
                flags[flag] = option.name

    return flags


def get_used_options() -> Dict[str, Dict[str, int]]:
    """
    Get the used options from the command-line arguments.

    Returns:
        Dict[str, Dict[str, int]]: A dictionary of used options and their counts.
    """
    flags = get_flags_from_context()
    used_options = {}

    for arg in sys.argv:
        cleaned_arg = arg if "=" not in arg else arg.split("=")[0]
        if cleaned_arg in flags:
            option_used = flags.get(cleaned_arg)

            if option_used in used_options:
                used_options[option_used][cleaned_arg] = (
                    used_options[option_used].get(cleaned_arg, 0) + 1
                )
            else:
                used_options[option_used] = {cleaned_arg: 1}

    return used_options


def get_version() -> str:
    """
    Get the version of Safety.

    Returns:
        str: The Safety version.
    """
    from importlib.metadata import version

    return version("safety")


def get_primary_announcement(
    announcements: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """
    Get the primary announcement from a list of announcements.

    Args:
        announcements (List[Dict[str, Any]]): The list of announcements.

    Returns:
        Optional[Dict[str, Any]]: The primary announcement if found, None otherwise.
    """
    for announcement in announcements:
        if announcement.get("type", "").lower() == "primary_announcement":
            try:
                from safety.output_utils import build_primary_announcement

                build_primary_announcement(announcement, columns=80)
            except Exception as e:
                LOG.debug(f"Failed to build primary announcement: {str(e)}")
                return None

            return announcement

    return None


def get_basic_announcements(
    announcements: List[Dict[str, Any]], include_local: bool = True
) -> List[Dict[str, Any]]:
    """
    Get the basic announcements from a list of announcements.

    Args:
        announcements (List[Dict[str, Any]]): The list of announcements.
        include_local (bool): Whether to include local announcements.

    Returns:
        List[Dict[str, Any]]: The list of basic announcements.
    """
    return [
        announcement
        for announcement in announcements
        if announcement.get("type", "").lower() != "primary_announcement"
        and not announcement.get("local", False)
        or (announcement.get("local", False) and include_local)
    ]


def filter_announcements(
    announcements: List[Dict[str, Any]], by_type: str = "error"
) -> List[Dict[str, Any]]:
    """
    Filter announcements by type.

    Args:
        announcements (List[Dict[str, Any]]): The list of announcements.
        by_type (str): The type of announcements to filter by.

    Returns:
        List[Dict[str, Any]]: The filtered announcements.
    """
    return [
        announcement
        for announcement in announcements
        if announcement.get("type", "").lower() == by_type
    ]


def build_telemetry_data(
    telemetry: bool = True,
    command: Optional[str] = None,
    subcommand: Optional[str] = None,
) -> TelemetryModel:
    """Build telemetry data for the Safety context.

    Args:
        telemetry (bool): Whether telemetry is enabled.
        command (Optional[str]): The command.
        subcommand (Optional[str]): The subcommand.

    Returns:
        TelemetryModel: The telemetry data model.
    """
    context = SafetyContext()

    body = (
        {
            "os_type": os.environ.get("SAFETY_OS_TYPE", None) or platform.system(),
            "os_release": os.environ.get("SAFETY_OS_RELEASE", None)
            or platform.release(),
            "os_description": os.environ.get("SAFETY_OS_DESCRIPTION", None)
            or platform.platform(),
            "python_version": platform.python_version(),
            "safety_command": command if command else context.command,
            "safety_options": get_used_options(),
        }
        if telemetry
        else {}
    )

    body["safety_version"] = get_version()
    body["safety_source"] = (
        os.environ.get("SAFETY_SOURCE", None) or context.safety_source
    )

    if "safety_options" not in body:
        body["safety_options"] = {}

    LOG.debug(f"Telemetry body built: {body}")

    return TelemetryModel(**body)


def build_git_data() -> Dict[str, Any]:
    """Build git data for the repository.

    Returns:
        Dict[str, str]: The git data.
    """
    import subprocess

    def git_command(commandline: List[str]) -> str:
        return (
            subprocess.run(
                commandline, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            .stdout.decode("utf-8")
            .strip()
        )

    try:
        is_git = git_command(["git", "rev-parse", "--is-inside-work-tree"])
    except Exception:
        is_git = False

    if is_git == "true":
        result = {"branch": "", "tag": "", "commit": "", "dirty": "", "origin": ""}

        try:
            result["branch"] = git_command(
                ["git", "symbolic-ref", "--short", "-q", "HEAD"]
            )
            result["tag"] = git_command(["git", "describe", "--tags", "--exact-match"])

            commit = git_command(
                ["git", "describe", '--match=""', "--always", "--abbrev=40", "--dirty"]
            )
            result["dirty"] = str(commit.endswith("-dirty"))
            result["commit"] = commit.split("-dirty")[0]

            result["origin"] = git_command(["git", "remote", "get-url", "origin"])
        except Exception:
            pass

        return result
    else:
        return {"error": "not-git-repo"}


def build_remediation_info_url(
    base_url: str, version: Optional[str], spec: str, target_version: Optional[str] = ""
) -> Optional[str]:
    """
    Build the remediation info URL.

    Args:
        base_url (str): The base URL.
        version (Optional[str]): The current version.
        spec (str): The specification.
        target_version (Optional[str]): The target version.

    Returns:
        str: The remediation info URL.
    """

    params = {"from": version, "to": target_version}

    # No pinned version
    if not version:
        params = {"spec": spec}

    req = PreparedRequest()
    req.prepare_url(base_url, params)

    return req.url


def get_processed_options(
    policy_file: Dict[str, Any],
    ignore: Dict[str, Any],
    ignore_severity_rules: Dict[str, Any],
    exit_code: bool,
    ignore_unpinned_requirements: Optional[bool] = None,
    project: Optional[str] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any], bool, Optional[bool], Optional[str]]:
    """
    Get processed options from the policy file.

    Args:
        policy_file (Dict[str, Any]): The policy file.
        ignore (Dict[str, Any]): The ignore settings.
        ignore_severity_rules (Dict[str, Any]): The ignore severity rules.
        exit_code (bool): The exit code setting.
        ignore_unpinned_requirements (Optional[bool]): The ignore unpinned requirements setting.
        project (Optional[str]): The project setting.

    Returns:
        Tuple[Dict[str, Any], Dict[str, Any], bool, Optional[bool], Optional[str]]: The processed options.
    """
    if policy_file:
        project_config = policy_file.get("project", {})
        security = policy_file.get("security", {})
        ctx = click.get_current_context()
        source = ctx.get_parameter_source("exit_code")

        if not project:
            project_id = project_config.get("id", None)
            if not project_id:
                project_id = None
            project = project_id

        if (
            ctx.get_parameter_source("ignore_unpinned_requirements")
            == click.core.ParameterSource.DEFAULT
        ):
            ignore_unpinned_requirements = security.get(
                "ignore-unpinned-requirements", None
            )

        if not ignore:
            ignore = security.get("ignore-vulnerabilities", {})
        if source == click.core.ParameterSource.DEFAULT:
            exit_code = not security.get("continue-on-vulnerability-error", False)
        ignore_cvss_below = security.get("ignore-cvss-severity-below", 0.0)
        ignore_cvss_unknown = security.get("ignore-cvss-unknown-severity", False)
        ignore_severity_rules = {
            "ignore-cvss-severity-below": ignore_cvss_below,
            "ignore-cvss-unknown-severity": ignore_cvss_unknown,
        }

    return (
        ignore,
        ignore_severity_rules,
        exit_code,
        ignore_unpinned_requirements,
        project,
    )


def get_fix_options(
    policy_file: Dict[str, Any], auto_remediation_limit: int
) -> Union[int, List[str]]:
    """
    Get fix options from the policy file.

    Args:
        policy_file (Dict[str, Any]): The policy file.
        auto_remediation_limit (int): The auto remediation limit.

    Returns:
        int: The auto remediation limit.
    """
    auto_fix = []

    source = click.get_current_context().get_parameter_source("auto_remediation_limit")
    if source == click.core.ParameterSource.COMMANDLINE:
        return auto_remediation_limit

    if policy_file:
        fix = policy_file.get("security-updates", {})
        auto_fix = fix.get("auto-security-updates-limit", None)
        if not auto_fix:
            auto_fix = []

    return auto_fix


class MutuallyExclusiveOption(click.Option):
    """
    A click option that is mutually exclusive with other options.
    """

    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop("mutually_exclusive", []))
        self.with_values = kwargs.pop("with_values", {})
        help = kwargs.get("help", "")
        if self.mutually_exclusive:
            ex_str = ", ".join(
                [
                    "{0} with values {1}".format(item, self.with_values.get(item))
                    if item in self.with_values
                    else item
                    for item in self.mutually_exclusive
                ]
            )
            kwargs["help"] = help + (
                " NOTE: This argument is mutually exclusive with "
                " arguments: [" + ex_str + "]."
            )
        super(MutuallyExclusiveOption, self).__init__(*args, **kwargs)

    def handle_parse_result(  # type: ignore
        self, ctx: click.Context, opts: Dict[str, Any], args: List[str]
    ) -> Tuple[Any, List[str]]:
        """
        Handle the parse result for mutually exclusive options.

        Args:
            ctx (click.Context): The click context.
            opts (Dict[str, Any]): The options dictionary.
            args (List[str]): The arguments list.

        Returns:
            Tuple[Any, List[str]]: The result and remaining arguments.
        """
        m_exclusive_used = self.mutually_exclusive.intersection(opts)
        option_used = m_exclusive_used and self.name in opts

        exclusive_value_used = False
        for used in m_exclusive_used:
            value_used = opts.get(used, None)
            if not isinstance(value_used, List):
                value_used = [value_used]
            if value_used and set(self.with_values.get(used, [])).intersection(
                value_used
            ):
                exclusive_value_used = True

        if option_used and (not self.with_values or exclusive_value_used):
            options = ", ".join(self.opts)
            prohibited = "".join(
                [
                    "\n * --{0} with {1}".format(item, self.with_values.get(item))
                    if item in self.with_values
                    else f"\n * {item}"
                    for item in self.mutually_exclusive
                ]
            )
            raise click.UsageError(
                f"Illegal usage: `{options}` is mutually exclusive with: {prohibited}"
            )

        return super(MutuallyExclusiveOption, self).handle_parse_result(ctx, opts, args)


class DependentOption(click.Option):
    """
    A click option that depends on other options.
    """

    def __init__(self, *args, **kwargs):
        self.required_options = set(kwargs.pop("required_options", []))
        help = kwargs.get("help", "")
        if self.required_options:
            ex_str = ", ".join(self.required_options)
            kwargs["help"] = help + (f" Requires: [ {ex_str} ]")
        super(DependentOption, self).__init__(*args, **kwargs)

    def handle_parse_result(  # type: ignore
        self, ctx: click.Context, opts: Dict[str, Any], args: List[str]
    ) -> Tuple[Any, List[str]]:
        """
        Handle the parse result for dependent options.

        Args:
            ctx (click.Context): The click context.
            opts (Dict[str, Any]): The options dictionary.
            args (List[str]): The arguments list.

        Returns:
            Tuple[Any, List[str]]: The result and remaining arguments.
        """
        missing_required_arguments = None

        if self.name in opts:
            missing_required_arguments = self.required_options.difference(opts)

        if missing_required_arguments:
            raise click.UsageError(
                "Illegal usage: `{}` needs the arguments `{}`.".format(
                    self.name, ", ".join(missing_required_arguments)
                )
            )

        return super(DependentOption, self).handle_parse_result(ctx, opts, args)


def transform_ignore(
    ctx: click.Context, param: click.Parameter, value: Tuple[str]
) -> Dict[str, Dict[str, Optional[str]]]:
    """
    Transform ignore parameters into a dictionary.

    Args:
        ctx (click.Context): The click context.
        param (click.Parameter): The click parameter.
        value (Tuple[str]): The parameter value.

    Returns:
        Dict[str, Dict[str, Optional[str]]]: The transformed ignore parameters.
    """
    ignored_default_dict = {"reason": "", "expires": None}
    if isinstance(value, tuple) and any(value):
        # Following code is required to support the 2 ways of providing 'ignore'
        # --ignore=1234,567,789
        # or, the historical way (supported for backward compatibility)
        # -i 1234 -i 567
        combined_value = ",".join(value)
        ignore_ids = {vuln_id.strip() for vuln_id in combined_value.split(",")}
        return {ignore_id: dict(ignored_default_dict) for ignore_id in ignore_ids}

    return {}


def active_color_if_needed(
    ctx: click.Context, param: click.Parameter, value: str
) -> str:
    """
    Activate color if needed based on the context and environment variables.

    Args:
        ctx (click.Context): The click context.
        param (click.Parameter): The click parameter.
        value (str): The parameter value.

    Returns:
        str: The parameter value.
    """
    if value == "screen":
        ctx.color = True

    color = os.environ.get("SAFETY_COLOR", None)

    if color is not None:
        color = color.lower()

        if color == "1" or color == "true":
            ctx.color = True
        elif color == "0" or color == "false":
            ctx.color = False

    return value


def json_alias(
    ctx: click.Context, param: click.Parameter, value: bool
) -> Optional[bool]:
    """
    Set the SAFETY_OUTPUT environment variable to 'json' if the parameter is used.

    Args:
        ctx (click.Context): The click context.
        param (click.Parameter): The click parameter.
        value (bool): The parameter value.

    Returns:
        bool: The parameter value.
    """
    if value:
        os.environ["SAFETY_OUTPUT"] = "json"
        return value


def html_alias(
    ctx: click.Context, param: click.Parameter, value: bool
) -> Optional[bool]:
    """
    Set the SAFETY_OUTPUT environment variable to 'html' if the parameter is used.

    Args:
        ctx (click.Context): The click context.
        param (click.Parameter): The click parameter.
        value (bool): The parameter value.

    Returns:
        bool: The parameter value.
    """
    if value:
        os.environ["SAFETY_OUTPUT"] = "html"
        return value


def bare_alias(
    ctx: click.Context, param: click.Parameter, value: bool
) -> Optional[bool]:
    """
    Set the SAFETY_OUTPUT environment variable to 'bare' if the parameter is used.

    Args:
        ctx (click.Context): The click context.
        param (click.Parameter): The click parameter.
        value (bool): The parameter value.

    Returns:
        bool: The parameter value.
    """
    if value:
        os.environ["SAFETY_OUTPUT"] = "bare"
        return value


def get_terminal_size() -> os.terminal_size:
    """
    Get the terminal size.

    Returns:
        os.terminal_size: The terminal size.
    """
    from shutil import get_terminal_size as t_size
    # get_terminal_size can report 0, 0 if run from pseudo-terminal prior Python 3.11 versions

    columns = t_size().columns or 80
    lines = t_size().lines or 24

    return os.terminal_size((columns, lines))


def clean_project_id(input_string: str) -> str:
    """
    Clean a project ID by removing non-alphanumeric characters and normalizing the string.

    Args:
        input_string (str): The input string.

    Returns:
        str: The cleaned project ID.
    """
    input_string = re.sub(r"[^a-zA-Z0-9]+", "-", input_string)
    input_string = input_string.strip("-")
    input_string = input_string.lower()

    return input_string


def validate_expiration_date(expiration_date: Optional[str]) -> Optional[datetime]:
    """
    Validate an expiration date string.

    Args:
        expiration_date (str): The expiration date string.

    Returns:
        Optional[datetime]: The validated expiration date if valid, None otherwise.
    """
    d = None

    if expiration_date:
        try:
            d = datetime.strptime(expiration_date, "%Y-%m-%d")
        except ValueError:
            pass

        try:
            d = datetime.strptime(expiration_date, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    return d


class SafetyPolicyFile(click.ParamType):
    """
    Custom Safety Policy file to hold validations.
    """

    name = "filename"
    envvar_list_splitter = os.path.pathsep

    def __init__(
        self,
        mode: str = "r",
        encoding: Optional[str] = None,
        errors: str = "strict",
        pure: bool = os.environ.get("SAFETY_PURE_YAML", "false").lower() == "true",
    ) -> None:
        self.mode = mode
        self.encoding = encoding
        self.errors = errors
        self.basic_msg = "\n" + click.style(
            'Unable to load the Safety Policy file "{name}".', fg="red"
        )
        self.pure = pure

    def to_info_dict(self) -> Dict[str, Any]:
        """
        Convert the object to an info dictionary.

        Returns:
            Dict[str, Any]: The info dictionary.
        """
        info_dict = super().to_info_dict()
        info_dict.update(mode=self.mode, encoding=self.encoding)
        return info_dict

    def fail_if_unrecognized_keys(
        self,
        used_keys: List[str],
        valid_keys: List[str],
        param: Optional[click.Parameter] = None,
        ctx: Optional[click.Context] = None,
        msg: str = "{hint}",
        context_hint: str = "",
    ) -> None:
        """
        Fail if unrecognized keys are found in the policy file.

        Args:
            used_keys (List[str]): The used keys.
            valid_keys (List[str]): The valid keys.
            param (Optional[click.Parameter]): The click parameter.
            ctx (Optional[click.Context]): The click context.
            msg (str): The error message template.
            context_hint (str): The context hint for the error message.

        Raises:
            click.UsageError: If unrecognized keys are found.
        """
        for keyword in used_keys:
            if keyword not in valid_keys:
                match = None
                max_ratio = 0.0
                if isinstance(keyword, str):
                    for option in valid_keys:
                        ratio = SequenceMatcher(None, keyword, option).ratio()
                        if ratio > max_ratio:
                            match = option
                            max_ratio = ratio

                maybe_msg = (
                    f" Maybe you meant: {match}"
                    if max_ratio > 0.7
                    else f" Valid keywords in this level are: {', '.join(valid_keys)}"
                )

                self.fail(
                    msg.format(
                        hint=f'{context_hint}"{keyword}" is not a valid keyword.{maybe_msg}'
                    ),
                    param,
                    ctx,
                )

    def fail_if_wrong_bool_value(
        self, keyword: str, value: Any, msg: str = "{hint}"
    ) -> None:
        """
        Fail if a boolean value is invalid.

        Args:
            keyword (str): The keyword.
            value (Any): The value.
            msg (str): The error message template.

        Raises:
            click.UsageError: If the boolean value is invalid.
        """
        if value is not None and not isinstance(value, bool):
            self.fail(
                msg.format(
                    hint=f"'{keyword}' value needs to be a boolean. "
                    "You can use True, False, TRUE, FALSE, true or false"
                )
            )

    def convert(
        self, value: Any, param: Optional[click.Parameter], ctx: Optional[click.Context]
    ) -> Any:
        """
        Convert the parameter value to a Safety policy file.

        Args:
            value (Any): The parameter value.
            param (Optional[click.Parameter]): The click parameter.
            ctx (Optional[click.Context]): The click context.

        Returns:
            Any: The converted policy file.

        Raises:
            click.UsageError: If the policy file is invalid.
        """
        try:
            # Check if the value is already a file-like object
            if hasattr(value, "read") or hasattr(value, "write"):
                return value

            # Prepare the error message template
            msg = (
                self.basic_msg.format(name=value)
                + "\n"
                + click.style("HINT:", fg="yellow")
                + " {hint}"
            )

            # Open the file stream
            f, _ = click.types.open_stream(  # type: ignore
                value, self.mode, self.encoding, self.errors, atomic=False
            )
            filename = ""

            try:
                # Read the content of the file
                raw = f.read()
                yaml = YAML(typ="safe", pure=self.pure)
                safety_policy = yaml.load(raw)
                filename = f.name
                f.close()
            except Exception as e:
                # Handle YAML parsing errors
                show_parsed_hint = isinstance(e, MarkedYAMLError)
                hint = str(e)
                if show_parsed_hint:
                    hint = f"{str(e.problem).strip()} {str(e.context).strip()} {str(e.context_mark).strip()}"

                self.fail(msg.format(name=value, hint=hint), param, ctx)

            # Validate the structure of the safety policy
            if (
                not safety_policy
                or not isinstance(safety_policy, dict)
                or not safety_policy.get("security", None)
            ):
                hint = "you are missing the security root tag"
                try:
                    version = safety_policy["version"]
                    if version:
                        hint = (
                            f"{filename} is a policy file version {version}. "
                            "Legacy policy file parser only accepts versions minor than 3.0"
                            "\nNote: `safety check` command accepts policy file versions <= 2.0. Versions >= 2.0 are not supported."
                        )
                except Exception:
                    pass
                self.fail(msg.format(hint=hint), param, ctx)

            # Validate 'security' section keys
            security_config = safety_policy.get("security", {})
            security_keys = [
                "ignore-cvss-severity-below",
                "ignore-cvss-unknown-severity",
                "ignore-vulnerabilities",
                "continue-on-vulnerability-error",
                "ignore-unpinned-requirements",
            ]
            self.fail_if_unrecognized_keys(
                security_config.keys(),
                security_keys,
                param=param,
                ctx=ctx,
                msg=msg,
                context_hint='"security" -> ',
            )

            # Validate 'ignore-cvss-severity-below' value
            ignore_cvss_security_below = security_config.get(
                "ignore-cvss-severity-below", None
            )
            if ignore_cvss_security_below:
                limit = 0.0
                try:
                    limit = float(ignore_cvss_security_below)
                except ValueError:
                    self.fail(
                        msg.format(
                            hint="'ignore-cvss-severity-below' value needs to be an integer or float."
                        )
                    )
                if limit < 0 or limit > 10:
                    self.fail(
                        msg.format(
                            hint="'ignore-cvss-severity-below' needs to be a value between 0 and 10"
                        )
                    )

            # Validate 'continue-on-vulnerability-error' value
            continue_on_vulnerability_error = security_config.get(
                "continue-on-vulnerability-error", None
            )
            self.fail_if_wrong_bool_value(
                "continue-on-vulnerability-error", continue_on_vulnerability_error, msg
            )

            # Validate 'ignore-cvss-unknown-severity' value
            ignore_cvss_unknown_severity = security_config.get(
                "ignore-cvss-unknown-severity", None
            )
            self.fail_if_wrong_bool_value(
                "ignore-cvss-unknown-severity", ignore_cvss_unknown_severity, msg
            )

            # Validate 'ignore-vulnerabilities' section
            ignore_vulns = safety_policy.get("security", {}).get(
                "ignore-vulnerabilities", {}
            )
            if ignore_vulns:
                if not isinstance(ignore_vulns, dict):
                    self.fail(
                        msg.format(
                            hint="Vulnerability IDs under the 'ignore-vulnerabilities' key, need to "
                            "follow the convention 'ID_NUMBER:', probably you are missing a colon."
                        )
                    )

                normalized = {}

                for ignored_vuln_id, config in ignore_vulns.items():
                    ignored_vuln_config = config if config else {}

                    if not isinstance(ignored_vuln_config, dict):
                        self.fail(
                            msg.format(
                                hint=f"Wrong configuration under the vulnerability with ID: {ignored_vuln_id}"
                            )
                        )

                    context_msg = f'"security" -> "ignore-vulnerabilities" -> "{ignored_vuln_id}" -> '

                    self.fail_if_unrecognized_keys(
                        ignored_vuln_config.keys(),  # type: ignore
                        ["reason", "expires"],
                        param=param,
                        ctx=ctx,
                        msg=msg,
                        context_hint=context_msg,
                    )

                    reason = ignored_vuln_config.get("reason", "")
                    reason = str(reason) if reason else None
                    expires = ignored_vuln_config.get("expires", "")
                    expires = str(expires) if expires else None

                    try:
                        if int(ignored_vuln_id) < 0:
                            raise ValueError("Negative Vulnerability ID")
                    except ValueError:
                        self.fail(
                            msg.format(
                                hint=f"vulnerability id {ignored_vuln_id} under the 'ignore-vulnerabilities' root needs to "
                                f"be a positive integer"
                            )
                        )

                    # Validate expires date
                    d = validate_expiration_date(expires)

                    if expires and not d:
                        self.fail(
                            msg.format(
                                hint=f'{context_msg}expires: "{expires}" isn\'t a valid format '
                                f"for the expires keyword, "
                                "valid options are: YYYY-MM-DD or "
                                "YYYY-MM-DD HH:MM:SS"
                            )
                        )

                    normalized[str(ignored_vuln_id)] = {"reason": reason, "expires": d}

                safety_policy["security"]["ignore-vulnerabilities"] = normalized
                safety_policy["filename"] = filename
                safety_policy["raw"] = raw
            else:
                safety_policy["security"]["ignore-vulnerabilities"] = {}

            # Validate 'fix' section keys
            fix_config = safety_policy.get("fix", {})
            self.fail_if_unrecognized_keys(
                fix_config.keys(),
                ["auto-security-updates-limit"],
                param=param,
                ctx=ctx,
                msg=msg,
                context_hint='"fix" -> ',
            )
            auto_remediation_limit = fix_config.get("auto-security-updates-limit", None)

            if auto_remediation_limit:
                self.fail_if_unrecognized_keys(
                    auto_remediation_limit,
                    ["patch", "minor", "major"],
                    param=param,
                    ctx=ctx,
                    msg=msg,
                    context_hint='"auto-security-updates-limit" -> ',
                )

            return safety_policy
        except BadParameter as expected_e:
            raise expected_e
        except Exception as e:
            # Handle file not found errors gracefully, don't fail in the default case
            if ctx and isinstance(e, OSError):
                default = ctx.get_parameter_source
                source = (
                    default("policy_file")
                    if default("policy_file")
                    else default("policy_file_path")
                )
                if (
                    e.errno == 2
                    and source == click.core.ParameterSource.DEFAULT
                    and value == ".safety-policy.yml"
                ):
                    return None

            problem = click.style("Policy file YAML is not valid.")
            hint = click.style("HINT: ", fg="yellow") + str(e)
            self.fail(f"{problem}\n{hint}", param, ctx)

    def shell_complete(
        self, ctx: click.Context, param: click.Parameter, incomplete: str
    ):
        """
        Return a special completion marker that tells the completion
        system to use the shell to provide file path completions.

        Args:
            ctx (click.Context): The click context.
            param (click.Parameter): The click parameter.
            incomplete (str): The value being completed. May be empty.

        Returns:
            List[click.shell_completion.CompletionItem]: The completion items.

        .. versionadded:: 8.0
        """
        from click.shell_completion import CompletionItem

        return [CompletionItem(incomplete, type="file")]


class SingletonMeta(type):
    """
    A metaclass for singleton classes.
    """

    _instances: Dict[type, Any] = {}

    _lock: Lock = Lock()

    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        with cls._lock:
            if cls not in cls._instances:
                instance = super().__call__(*args, **kwargs)
                cls._instances[cls] = instance
        return cls._instances[cls]


class SafetyContext(metaclass=SingletonMeta):
    """
    A singleton class to hold the Safety context.
    """

    packages = []
    key = False
    db_mirror = False
    cached = None
    ignore_vulns = None
    ignore_severity_rules = None
    proxy = None
    include_ignored = False
    telemetry = None
    files = None
    stdin = None
    is_env_scan = None
    command: Optional[str] = None
    subcommand: Optional[str] = None
    review = None
    params = {}
    safety_source = "code"
    local_announcements = []
    scanned_full_path = []
    account = None


def sync_safety_context(f):
    """
    Decorator to sync the Safety context with the function arguments.
    """

    def new_func(*args, **kwargs):
        ctx = SafetyContext()

        legacy_key_added = False
        if "session" in kwargs:
            legacy_key_added = True
            session = kwargs.get("session")
            kwargs["key"] = session.api_key if session else None

        for attr in dir(ctx):
            if attr in kwargs:
                setattr(ctx, attr, kwargs.get(attr))

        if legacy_key_added:
            kwargs.pop("key")

        return f(*args, **kwargs)

    return new_func


@sync_safety_context
def get_packages_licenses(
    *,
    packages: Optional[List[Package]] = None,
    licenses_db: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Get the licenses for the specified packages based on their version.

    Args:
        packages (Optional[List[Package]]): The list of packages.
        licenses_db (Optional[Dict[str, Any]]): The licenses database.

    Returns:
        List[Dict[str, Any]]: The list of packages and their licenses.
    """
    SafetyContext().command = "license"

    if not packages:
        packages = []
    if not licenses_db:
        licenses_db = {}

    packages_licenses_db = licenses_db.get("packages", {})
    filtered_packages_licenses = []

    for pkg in packages:
        # Ignore recursive files not resolved
        if isinstance(pkg, RequirementFile):
            continue
        # normalize the package name
        pkg_name = canonicalize_name(pkg.name)
        # packages may have different licenses depending their version.
        pkg_licenses = packages_licenses_db.get(pkg_name, [])
        if not pkg.version:
            for req in pkg.requirements:
                if is_pinned_requirement(req.specifier):
                    pkg.version = next(iter(req.specifier)).version
                    break

            if not pkg.version:
                continue
        version_requested = parse_version(pkg.version)
        license_id = None
        license_name = None
        for pkg_version in pkg_licenses:
            license_start_version = parse_version(pkg_version["start_version"])
            # Stops and return the previous stored license when a new
            # license starts on a version above the requested one.
            if version_requested >= license_start_version:
                license_id = pkg_version["license_id"]
            else:
                # We found the license for the version requested
                break

        if license_id:
            license_name = get_license_name_by_id(license_id, licenses_db)
        if not license_id or not license_name:
            license_name = "unknown"

        filtered_packages_licenses.append(
            {"package": pkg_name, "version": pkg.version, "license": license_name}
        )

    return filtered_packages_licenses


def get_requirements_content(files: List[Any]) -> Dict[str, str]:
    """
    Get the content of the requirements files.

    Args:
        files (List[click.File]): The list of requirement files.

    Returns:
        Dict[str, str]: The content of the requirement files.

    Raises:
        InvalidProvidedReportError: If a file cannot be read.
    """
    requirements_files = {}

    for f in files:
        try:
            f.seek(0)
            requirements_files[f.name] = f.read()
            f.close()
        except Exception as e:
            raise InvalidProvidedReportError(
                message=f"Unable to read a requirement file scanned in the report. {e}"
            )

    return requirements_files


def is_ignore_unpinned_mode(version: str) -> bool:
    """
    Check if unpinned mode is enabled based on the version.

    Args:
        version (str): The version string.

    Returns:
        bool: True if unpinned mode is enabled, False otherwise.
    """
    ignore = SafetyContext().params.get("ignore_unpinned_requirements")
    return (ignore is None or ignore) and not version


def get_remediations_count(remediations: Dict[str, Any]) -> int:
    """
    Get the count of remediations.

    Args:
        remediations (Dict[str, Any]): The remediations dictionary.

    Returns:
        int: The count of remediations.
    """
    return sum((len(rem.keys()) for pkg, rem in remediations.items()))


def get_hashes(dependency: Any) -> List[Dict[str, str]]:
    """
    Get the hashes for a dependency.

    Args:
        dependency (Any): The dependency.

    Returns:
        List[Dict[str, str]]: The list of hashes.
    """
    pattern = re.compile(HASH_REGEX_GROUPS)

    return [
        {"method": method, "hash": hsh}
        for method, hsh in (
            pattern.match(d_hash).groups()  # type: ignore
            for d_hash in dependency.hashes
        )
    ]


def pluralize(word: str, count: int = 0) -> str:
    """
    Pluralize a word based on the count.

    Args:
        word (str): The word to pluralize.
        count (int): The count.

    Returns:
        str: The pluralized word.
    """
    if count == 1:
        return word

    default = {"was": "were", "this": "these", "has": "have"}

    if word in default:
        return default[word]

    if (
        word.endswith("s")
        or word.endswith("x")
        or word.endswith("z")
        or word.endswith("ch")
        or word.endswith("sh")
    ):
        return word + "es"

    if word.endswith("y"):
        if word[-2] in "aeiou":
            return word + "s"
        else:
            return word[:-1] + "ies"

    return word + "s"


def initialize_config_dirs() -> None:
    """
    Initialize the configuration directories.
    """
    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    try:
        SYSTEM_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def initialize_event_bus(ctx: Union["CustomContext", "typer.Context"]) -> bool:
    """
    Initializes the event bus for the given context. This should be called one
    time only per command run.
    The event bus requires the following conditions to be met:
    - Platform OR Platform and Firewall features enabled
    - Authenticated user
    Args:
        ctx (CustomContext): The context object containing necessary
                             information.
    Returns:
        bool: True if the event bus was successfully initialized,
              False otherwise.
    """
    try:
        obj: "SafetyCLI" = ctx.obj
        auth: Optional["Auth"] = None

        if obj and obj.events_enabled and (auth := getattr(obj, "auth", None)):
            client: "SafetyAuthSession" = auth.client
            token = client.token.get("access_token") if client.token else None

            # Start the event bus if the user has set up authn
            if client and bool(token or client.api_key):
                start_event_bus(obj, client)

                if event_bus := obj.event_bus:
                    # Trigger here CLI GROUP LOADED event
                    from safety.events.utils import (
                        create_internal_event,
                        InternalEventType,
                        InternalPayload,
                    )

                    event = create_internal_event(
                        event_type=InternalEventType.EVENT_BUS_READY,
                        payload=InternalPayload(ctx=ctx),
                    )

                    event_bus.emit(event)

                    return True

    except Exception as e:
        LOG.exception("Error starting event bus: %s", e)

    return False
