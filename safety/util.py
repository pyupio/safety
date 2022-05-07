import logging
import os
import platform
import sys
from datetime import datetime
from typing import List

import click
from _ruamel_yaml import ScannerError
from dparse.parser import setuptools_parse_requirements_backport as _parse_requirements
from packaging.utils import canonicalize_name
from packaging.version import parse as parse_version
from ruamel.yaml import YAML

from safety.constants import EXIT_CODE_FAILURE, EXIT_CODE_OK
from safety.models import Package, RequirementFile

LOG = logging.getLogger(__name__)

def iter_lines(fh, lineno=0):
    for line in fh.readlines()[lineno:]:
        yield line


def parse_line(line):
    if line.startswith('-e') or line.startswith('http://') or line.startswith('https://'):
        if "#egg=" in line:
            line = line.split("#egg=")[-1]
    if ' --hash' in line:
        line = line.split(" --hash")[0]
    return _parse_requirements(line)


def read_requirements(fh, resolve=False):
    """
    Reads requirements from a file like object and (optionally) from referenced files.
    :param fh: file like object to read from
    :param resolve: boolean. resolves referenced files.
    :return: generator
    """
    is_temp_file = not hasattr(fh, 'name')
    for num, line in enumerate(iter_lines(fh)):
        line = line.strip()
        if not line:
            # skip empty lines
            continue
        if line.startswith('#') or \
            line.startswith('-i') or \
            line.startswith('--index-url') or \
            line.startswith('--extra-index-url') or \
            line.startswith('-f') or line.startswith('--find-links') or \
            line.startswith('--no-index') or line.startswith('--allow-external') or \
            line.startswith('--allow-unverified') or line.startswith('-Z') or \
            line.startswith('--always-unzip'):
            # skip unsupported lines
            continue
        elif line.startswith('-r') or line.startswith('--requirement'):
            # got a referenced file here, try to resolve the path
            # if this is a tempfile, skip
            if is_temp_file:
                continue

            # strip away the recursive flag
            prefixes = ["-r", "--requirement"]
            filename = line.strip()
            for prefix in prefixes:
                if filename.startswith(prefix):
                    filename = filename[len(prefix):].strip()

            # if there is a comment, remove it
            if " #" in filename:
                filename = filename.split(" #")[0].strip()
            req_file_path = os.path.join(os.path.dirname(fh.name), filename)
            if resolve:
                # recursively yield the resolved requirements
                if os.path.exists(req_file_path):
                    with open(req_file_path) as _fh:
                        for req in read_requirements(_fh, resolve=True):
                            yield req
            else:
                yield RequirementFile(path=req_file_path)
        else:
            try:
                parseable_line = line
                # multiline requirements are not parseable
                if "\\" in line:
                    parseable_line = line.replace("\\", "")
                    for next_line in iter_lines(fh, num + 1):
                        parseable_line += next_line.strip().replace("\\", "")
                        line += "\n" + next_line
                        if "\\" in next_line:
                            continue
                        break
                req, = parse_line(parseable_line)
                if len(req.specifier._specs) == 1 and \
                        next(iter(req.specifier._specs))._spec[0] == "==":
                    yield Package(name=req.name, version=next(iter(req.specifier._specs))._spec[1],
                                  found='temp_file' if is_temp_file else fh.name, insecure_versions=[],
                                  secure_versions=[], latest_version=None,
                                  latest_version_without_known_vulnerabilities=None, more_info_url=None)
                else:
                    try:
                        fname = fh.name
                    except AttributeError:
                        fname = line

                    click.secho(
                        "Warning: unpinned requirement '{req}' found in {fname}, "
                        "unable to check.".format(req=req.name,
                                                  fname=fname),
                        fg="yellow",
                        file=sys.stderr
                    )
            except ValueError:
                continue


def get_proxy_dict(proxy_protocol, proxy_host, proxy_port):
    if proxy_protocol and proxy_host and proxy_port:
        return {proxy_protocol: f"{proxy_protocol}://{proxy_host}:{str(proxy_port)}"}
    return None


def get_license_name_by_id(license_id, db):
    licenses = db.get('licenses', [])
    for name, id in licenses.items():
        if id == license_id:
            return name
    return None


def get_packages_licenses(packages, licenses_db):
    """Get the licenses for the specified packages based on their version.

    :param packages: packages list
    :param licenses_db: the licenses db in the raw form.
    :return: list of objects with the packages and their respectives licenses.
    """
    packages_licenses_db = licenses_db.get('packages', {})
    filtered_packages_licenses = []

    for pkg in packages:
        # Ignore recursive files not resolved
        if isinstance(pkg, RequirementFile):
            continue
        # normalize the package name
        pkg_name = canonicalize_name(pkg.name)
        # packages may have different licenses depending their version.
        pkg_licenses = packages_licenses_db.get(pkg_name, [])
        version_requested = parse_version(pkg.version)
        license_id = None
        license_name = None
        for pkg_version in pkg_licenses:
            license_start_version = parse_version(pkg_version['start_version'])
            # Stops and return the previous stored license when a new
            # license starts on a version above the requested one.
            if version_requested >= license_start_version:
                license_id = pkg_version['license_id']
            else:
                # We found the license for the version requested
                break

        if license_id:
            license_name = get_license_name_by_id(license_id, licenses_db)
        if not license_id or not license_name:
            license_name = "unknown"

        filtered_packages_licenses.append({
            "package": pkg_name,
            "version": pkg.version,
            "license": license_name
        })

    return filtered_packages_licenses


def get_flags_from_context():
    flags = {}
    context = click.get_current_context()

    for option in context.command.params:
        flags_per_opt = option.opts + option.secondary_opts
        for flag in flags_per_opt:
            flags[flag] = option.name

    return flags


def get_used_options():
    flags = get_flags_from_context()
    used_options = {}

    for arg in sys.argv:
        cleaned_arg = arg if '=' not in arg else arg.split('=')[0]
        if cleaned_arg in flags:
            option_used = flags.get(cleaned_arg)

            if option_used in used_options:
                used_options[option_used][cleaned_arg] = used_options[option_used].get(cleaned_arg, 0) + 1
            else:
                used_options[option_used] = {cleaned_arg: 1}

    return used_options


def get_safety_version():
    from safety import VERSION
    return VERSION


def get_primary_announcement(announcements):
    for announcement in announcements:
        if announcement.get('type', '').lower() == 'primary_announcement':
            return announcement

    return None


def get_basic_announcements(announcements):
    return [announcement for announcement in announcements if
            announcement.get('type', '').lower() != 'primary_announcement']


def build_telemetry_data(telemetry=True):
    body = {
        'os_type': platform.system(),
        'os_release': platform.release(),
        'os_description': platform.platform(),
        'python_version': platform.python_version(),
        'safety_command': click.get_current_context().command.name,
        'safety_options': get_used_options()
    } if telemetry else {}

    body['safety_version'] = get_safety_version()

    LOG.debug(f'Telemetry body built: {body}')

    return body


def output_exception(exception, exit_code_output=True):
    click.secho(str(exception), fg="red", file=sys.stderr)

    if exit_code_output:
        exit_code = EXIT_CODE_FAILURE
        if hasattr(exception, 'get_exit_code'):
            exit_code = exception.get_exit_code()
    else:
        exit_code = EXIT_CODE_OK

    sys.exit(exit_code)


def get_processed_options(policy_file, ignore, ignore_severity_rules, exit_code):
    if policy_file:
        security = policy_file.get('security', {})
        source = click.get_current_context().get_parameter_source("exit_code")

        if not ignore:
            ignore = security.get('ignore-vulnerabilities', {})
        if source == click.core.ParameterSource.DEFAULT:
            exit_code = not security.get('continue-on-vulnerability-error', False)
        ignore_cvss_below = security.get('ignore-cvss-severity-below', 0.0)
        ignore_cvss_unknown = security.get('ignore-cvss-unknown-severity', False)
        ignore_severity_rules = {'ignore-cvss-severity-below': ignore_cvss_below,
                                 'ignore-cvss-unknown-severity': ignore_cvss_unknown}

    return ignore, ignore_severity_rules, exit_code


class MutuallyExclusiveOption(click.Option):
    def __init__(self, *args, **kwargs):
        self.mutually_exclusive = set(kwargs.pop('mutually_exclusive', []))
        self.with_values = kwargs.pop('with_values', {})
        help = kwargs.get('help', '')
        if self.mutually_exclusive:
            ex_str = ', '.join(["{0} with values {1}".format(item, self.with_values.get(item)) if item in self.with_values else item for item in self.mutually_exclusive])
            kwargs['help'] = help + (
                ' NOTE: This argument is mutually exclusive with '
                ' arguments: [' + ex_str + '].'
            )
        super(MutuallyExclusiveOption, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        m_exclusive_used = self.mutually_exclusive.intersection(opts)
        option_used = m_exclusive_used and self.name in opts

        exclusive_value_used = False
        for used in m_exclusive_used:
            value_used = opts.get(used, None)
            if not isinstance(value_used, List):
                value_used = [value_used]
            if value_used and set(self.with_values.get(used, [])).intersection(value_used):
                exclusive_value_used = True

        if option_used and (not self.with_values or exclusive_value_used):
            raise click.UsageError(
                "Illegal usage: `{}` is mutually exclusive with "
                "arguments `{}`.".format(
                    self.name,
                    ', '.join(["{0} with values {1}".format(item, self.with_values.get(
                        item)) if item in self.with_values else item for item in self.mutually_exclusive])
                )
            )

        return super(MutuallyExclusiveOption, self).handle_parse_result(
            ctx,
            opts,
            args
        )


class DependentOption(click.Option):
    def __init__(self, *args, **kwargs):
        self.required_options = set(kwargs.pop('required_options', []))
        help = kwargs.get('help', '')
        if self.required_options:
            ex_str = ', '.join(self.required_options)
            kwargs['help'] = help + (
                ' NOTE: This argument requires the following flags '
                ' [' + ex_str + '].'
            )
        super(DependentOption, self).__init__(*args, **kwargs)

    def handle_parse_result(self, ctx, opts, args):
        missing_required_arguments = self.required_options.difference(opts) and self.name in opts

        if missing_required_arguments:
            raise click.UsageError(
                "Illegal usage: `{}` needs the "
                "arguments `{}`.".format(
                    self.name,
                    ', '.join(missing_required_arguments)
                )
            )

        return super(DependentOption, self).handle_parse_result(
            ctx,
            opts,
            args
        )


def transform_ignore(ctx, param, value):
    if isinstance(value, tuple):
        return dict(zip(value, [{'reason': '', 'expires': None} for _ in range(len(value))]))

    return {}


def active_color_if_needed(ctx, param, value):
    if value == 'screen':
        ctx.color = True

    color = os.environ.get("SAFETY_COLOR", None)

    if color is not None:
        ctx.color = bool(color)

    return value


class SafetyPolicyFile(click.ParamType):
    """Declares a parameter to be a file for reading or writing.  The file
    is automatically closed once the context tears down (after the command
    finished working).

    Files can be opened for reading or writing.  The special value ``-``
    indicates stdin or stdout depending on the mode.

    By default, the file is opened for reading text data, but it can also be
    opened in binary mode or for writing.  The encoding parameter can be used
    to force a specific encoding.

    The `lazy` flag controls if the file should be opened immediately or upon
    first IO. The default is to be non-lazy for standard input and output
    streams as well as files opened for reading, `lazy` otherwise. When opening a
    file lazily for reading, it is still opened temporarily for validation, but
    will not be held open until first IO. lazy is mainly useful when opening
    for writing to avoid creating the file until it is needed.

    Starting with Click 2.0, files can also be opened atomically in which
    case all writes go into a separate file in the same folder and upon
    completion the file will be moved over to the original location.  This
    is useful if a file regularly read by other users is modified.

    See :ref:`file-args` for more information.
    """

    name = "filename"
    envvar_list_splitter = os.path.pathsep

    def __init__(
        self,
        mode: str = "r",
        encoding: str = None,
        errors: str = "strict",
    ) -> None:
        self.mode = mode
        self.encoding = encoding
        self.errors = errors

    def to_info_dict(self):
        info_dict = super().to_info_dict()
        info_dict.update(mode=self.mode, encoding=self.encoding)
        return info_dict

    def convert(self, value, param, ctx):
        try:
            if hasattr(value, "read") or hasattr(value, "write"):
                return value

            basic_msg = 'Unable to load the Safety Policy file "{name}".'.format(name=value)
            msg = basic_msg + '\nHINT: {hint}'

            f, should_close = click.types.open_stream(
                value, self.mode, self.encoding, self.errors, atomic=False
            )
            filename = ''

            try:
                yaml = YAML(typ='safe', pure=False)
                safety_policy = yaml.load(f)
                filename = f.name
            except ScannerError as e:
                hint = '{0} {1}; {2} {3}'.format(str(e.context).strip(), str(e.context_mark).strip(), str(e.problem).strip(),
                                                 str(e.problem_mark).strip())
                self.fail(msg.format(name=value, hint=hint), param, ctx)

            if not safety_policy or not isinstance(safety_policy, dict) or not safety_policy.get('security', None):
                self.fail(
                    msg.format(hint='you are missing the security root tag'), param, ctx)

            ignore_cvss_security_below = safety_policy.get('security', {}).get('ignore-cvss-severity-below', None)

            if ignore_cvss_security_below:
                limit = 0.0

                try:
                    limit = float(ignore_cvss_security_below)
                except ValueError as e:
                    self.fail(msg.format(hint="'ignore-cvss-severity-below' value needs to be an integer or float."))

                if limit < 0 or limit > 10:
                    self.fail(msg.format(hint="'ignore-cvss-severity-below' needs to be a value between 0 and 10"))

            continue_on_vulnerability_error = safety_policy.get('security', {}).get('continue-on-vulnerability-error', None)

            if continue_on_vulnerability_error and not isinstance(continue_on_vulnerability_error, bool):
                self.fail(msg.format(hint="'continue-on-vulnerability-error' value needs to be a boolean."))

            ignore_vulns = safety_policy.get('security', {}).get('ignore-vulnerabilities', {})

            if ignore_vulns:
                normalized = {
                    str(key): {'reason': str((value if value else {}).get('reason', '')), 'expires': str((value if value else {}).get('expires', ''))} for
                    key, value in ignore_vulns.items()}

                for key, value in ignore_vulns.items():
                    try:
                        k = str(key)
                    except ValueError as e:
                        self.fail(msg.format(
                            hint="vulnerability id under the 'ignore-vulnerabilities' root needs to be a string or int")
                        )

                    # Validate expires
                    expires = str((value if value else {}).get('expires', ''))
                    d = None
                    if expires:
                        try:
                            d = datetime.strptime(expires, '%Y-%m-%d')
                        except ValueError as e:
                            pass

                        try:
                            d = datetime.strptime(expires, '%Y-%m-%d %H:%M:%S')
                        except ValueError as e:
                            pass

                        if not d:
                            self.fail(msg.format(hint="{0} isn't a valid format for the expires keyword, "
                                                      "valid options are: YYYY-MM-DD or "
                                                      "YYYY-MM-DD HH:MM:SS".format(expires))
                                      )

                    normalized[k] = {'reason': str((value if value else {}).get('reason', '')),
                                     'expires': d}

                safety_policy['security']['ignore-vulnerabilities'] = normalized
                safety_policy['filename'] = filename

            return safety_policy
        except OSError as e:
            # Don't fail in the default case
            source = ctx.get_parameter_source("policy_file")
            if e.errno == 2 and source == click.core.ParameterSource.DEFAULT and value == '.safety-policy.yml':
                return None

            self.fail(f"{os.fsdecode(value)!r}: {e.strerror}", param, ctx)

    def shell_complete(
        self, ctx: "Context", param: "Parameter", incomplete: str
    ):
        """Return a special completion marker that tells the completion
        system to use the shell to provide file path completions.

        :param ctx: Invocation context for this command.
        :param param: The parameter that is requesting completion.
        :param incomplete: Value being completed. May be empty.

        .. versionadded:: 8.0
        """
        from click.shell_completion import CompletionItem

        return [CompletionItem(incomplete, type="file")]
