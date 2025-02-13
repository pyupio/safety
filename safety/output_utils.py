import json
import logging
import os
import textwrap
from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import click
from jinja2 import Environment, PackageLoader

from safety.constants import RED, YELLOW
from safety.meta import get_version
from safety.models import Fix, is_pinned_requirement
from safety.util import (
    Package,
    SafetyContext,
    build_git_data,
    build_telemetry_data,
    get_remediations_count,
    get_terminal_size,
    is_a_remote_mirror,
)

LOG = logging.getLogger(__name__)


def build_announcements_section_content(announcements: List[Dict[str, Any]], columns: int = get_terminal_size().columns, indent: str = ' ' * 2, sub_indent: str = ' ' * 4) -> str:
    """
    Build the content for the announcements section.

    Args:
        announcements (List[Dict[str, Any]]): List of announcements.
        columns (int, optional): Number of columns for formatting. Defaults to terminal size.
        indent (str, optional): Indentation for the text. Defaults to ' ' * 2.
        sub_indent (str, optional): Sub-indentation for the text. Defaults to ' ' * 4.

    Returns:
        str: Formatted announcements section content.
    """
    section = ''

    for i, announcement in enumerate(announcements):

        color = ''
        if announcement.get('type') == 'error':
            color = RED
        elif announcement.get('type') == 'warning':
            color = YELLOW

        message = f"* {announcement.get('message')}"
        section += format_long_text(message, color, columns, indent=indent, sub_indent=sub_indent,
                                    start_line_decorator='', end_line_decorator=' ')

        if i + 1 < len(announcements):
            section += '\n'

    return section


def add_empty_line() -> str:
    """
    Add an empty line.

    Returns:
        str: Empty line.
    """
    return format_long_text('')


def style_lines(lines: List[Dict[str, Any]], columns: int, pre_processed_text: str = '', start_line: str = ' ' * 4, end_line: str = ' ' * 4) -> str:
    """
    Style the lines with the specified format.

    Args:
        lines (List[Dict[str, Any]]): List of lines to style.
        columns (int): Number of columns for formatting.
        pre_processed_text (str, optional): Pre-processed text. Defaults to ''.
        start_line (str, optional): Starting line decorator. Defaults to ' ' * 4.
        end_line (str, optional): Ending line decorator. Defaults to ' ' * 4.

    Returns:
        str: Styled text.
    """
    styled_text = pre_processed_text

    for line in lines:
        styled_line = ''
        left_padding = ' ' * line.get('indent', 0)

        for i, word in enumerate(line.get('words', [])):
            if word.get('style', {}):
                text = ''

                if i == 0:
                    text = left_padding  # Include the line padding in the word to avoid Github issues
                    left_padding = ''  # Clean left padding to avoid be added two times

                text += word.get('value', '')

                styled_line += click.style(text=text, **word.get('style', {}))
            else:
                styled_line += word.get('value', '')

        styled_text += format_long_text(styled_line, columns=columns, start_line_decorator=start_line,
                                        end_line_decorator=end_line,
                                        indent=left_padding, **line.get('format', {})) + '\n'

    return styled_text


def format_vulnerability(vulnerability: Any, full_mode: bool, only_text: bool = False, columns: int = get_terminal_size().columns) -> str:
    """
    Format the vulnerability details.

    Args:
        vulnerability (Any): The vulnerability object.
        full_mode (bool): Whether to use full mode for formatting.
        only_text (bool, optional): Whether to return only text without styling. Defaults to False.
        columns (int, optional): Number of columns for formatting. Defaults to terminal size.

    Returns:
        str: Formatted vulnerability details.
    """

    common_format = {'indent': 3, 'format': {'sub_indent': ' ' * 3, 'max_lines': None}}

    styled_vulnerability = [
        {'words': [{'style': {'bold': True}, 'value': 'Vulnerability ID: '},
                   {'value': vulnerability.vulnerability_id}]},
    ]

    vulnerability_spec = [
        {'words': [{'style': {'bold': True}, 'value': 'Affected spec: '},
                   {'value': ', '.join(vulnerability.vulnerable_spec)}]}]

    is_pinned_req = is_pinned_requirement(vulnerability.analyzed_requirement.specifier)

    cve = vulnerability.CVE

    cvssv2_line = None
    cve_lines = []

    if cve:
        if full_mode and cve.cvssv2:
            b = cve.cvssv2.get("base_score", "-")
            s = cve.cvssv2.get("impact_score", "-")
            v = cve.cvssv2.get("vector_string", "-")

            cvssv2_line = {'words': [
                {'value': f'CVSS v2, BASE SCORE {b}, IMPACT SCORE {s}, VECTOR STRING {v}'},
            ]}

        if cve.cvssv3 and "base_severity" in cve.cvssv3.keys():
            cvss_base_severity_style = {'bold': True}
            base_severity = cve.cvssv3.get("base_severity", "-")

            if base_severity.upper() in ['HIGH', 'CRITICAL']:
                cvss_base_severity_style['fg'] = 'red'

            b = cve.cvssv3.get("base_score", "-")

            if full_mode:
                s = cve.cvssv3.get("impact_score", "-")
                v = cve.cvssv3.get("vector_string", "-")

                cvssv3_text = f'CVSS v3, BASE SCORE {b}, IMPACT SCORE {s}, VECTOR STRING {v}'

            else:
                cvssv3_text = f'CVSS v3, BASE SCORE {b} '

            cve_lines = [
                {'words': [{'style': {'bold': True}, 'value': '{0} is '.format(cve.name)},
                           {'style': cvss_base_severity_style,
                            'value': f'{base_severity} SEVERITY => '},
                           {'value': cvssv3_text},
                           ]},
            ]

            if cvssv2_line:
                cve_lines.append(cvssv2_line)

        elif cve.name:
            cve_lines = [
                {'words': [{'style': {'bold': True}, 'value': cve.name}]}
            ]

    advisory_format = {'sub_indent': ' ' * 3, 'max_lines': None} if full_mode else {'sub_indent': ' ' * 3,
                                                                                    'max_lines': 2}

    basic_vuln_data_lines = [
        {'format': advisory_format, 'words': [
            {'style': {'bold': True}, 'value': 'ADVISORY: '},
            {'value': vulnerability.advisory.replace('\n', '')}]}
    ]

    if is_using_api_key():
        fixed_version_line = {'words': [
            {'style': {'bold': True}, 'value': 'Fixed versions: '},
            {'value': ', '.join(vulnerability.fixed_versions) if vulnerability.fixed_versions else 'No known fix'}
        ]}

        basic_vuln_data_lines.append(fixed_version_line)

    more_info_line = [
        {'words': [{'style': {'bold': True}, 'value': 'For more information about this vulnerability, visit '},
                   {'value': click.style(vulnerability.more_info_url)}]}
    ]

    if not is_pinned_req and not vulnerability.ignored:
        more_info_line.insert(0, {'words': [
            {'style': {'bold': True}, 'value': f'This vulnerability is present in your install specifier range.'},
            {'value': f' {get_specifier_range_info()}'}
        ]})

    vuln_title = f'-> Vulnerability found in {vulnerability.package_name} version {vulnerability.analyzed_version}'

    if not is_pinned_req:
        vuln_title = f'-> Vulnerability may be present given that your {vulnerability.package_name} install specifier' \
                     f' is {vulnerability.analyzed_requirement.specifier}'

    title_color: str = 'red'
    to_print = styled_vulnerability

    if not vulnerability.ignored:
        to_print += vulnerability_spec + basic_vuln_data_lines + cve_lines
    else:
        title_color = ''
        generic_reason = 'This vulnerability is being ignored'
        if vulnerability.ignored_expires:
            generic_reason += f" until {vulnerability.ignored_expires.strftime('%Y-%m-%d %H:%M:%S UTC')}. " \
                              f"See your configurations"

        specific_reason = None
        if vulnerability.ignored_reason:
            specific_reason = [
                {'words': [{'style': {'bold': True}, 'value': 'Reason: '}, {'value': vulnerability.ignored_reason}]}]

        expire_section = [{'words': [
            {'style': {'bold': True, 'fg': 'green'}, 'value': f'{generic_reason}.'}, ]}]

        if specific_reason:
            expire_section += specific_reason

        to_print += expire_section

    to_print += more_info_line

    if not vulnerability.ignored:
        ignore_help_line = [
            {'words': [
                {
                    'value': f'To ignore this vulnerability, use PyUp vulnerability id {vulnerability.vulnerability_id}'
                             f' in safety’s ignore command-line argument or add the ignore to your safety policy file.'
                    }
            ]}
        ]

        to_print += ignore_help_line

    to_print = [{**common_format, **line} for line in to_print]

    styled_text = format_long_text(vuln_title, title_color, columns, start_line_decorator='', end_line_decorator='',
                                   sub_indent=' ' * 3) + '\n'

    content = style_lines(to_print, columns - 3, styled_text, start_line='', end_line='')

    return click.unstyle(content) if only_text else content


def format_license(license: Dict[str, Any], only_text: bool = False, columns: int = get_terminal_size().columns) -> str:
    """
    Format the license details.

    Args:
        license (Dict[str, Any]): The license details.
        only_text (bool, optional): Whether to return only text without styling. Defaults to False.
        columns (int, optional): Number of columns for formatting. Defaults to terminal size.

    Returns:
        str: Formatted license details.
    """
    to_print = [
        {'words': [{'style': {'bold': True}, 'value': license['package']},
                   {'value': ' version {0} found using license '.format(license['version'])},
                   {'style': {'bold': True}, 'value': license['license']}
                   ]
         },
    ]

    content = style_lines(to_print, columns, '-> ', start_line='', end_line='')

    return click.unstyle(content) if only_text else content


def get_fix_hint_for_unpinned(remediation: Dict[str, Any]) -> str:
    """
    Get the fix hint for unpinned dependencies.

    Args:
        remediation (Dict[str, Any]): The remediation details.

    Returns:
        str: The fix hint.
    """
    secure_options: List[str] = [str(fix) for fix in remediation.get('other_recommended_versions', [])]
    fixes_hint = f'Version {remediation.get("recommended_version")} has no known vulnerabilities and falls' \
                 f' within your current specifier range.'

    if len(secure_options) > 0:
        other_options_msg = build_other_options_msg(fix_version=remediation.get("recommended_version"), is_spec=True,
                                                    secure_options=secure_options)
        fixes_hint += f' {other_options_msg}'

    return fixes_hint


def get_unpinned_hint(pkg: str) -> str:
    """
    Get the hint for unpinned packages.

    Args:
        pkg (str): The package name.

    Returns:
        str: The hint for unpinned packages.
    """
    return f"We recommend either pinning {pkg} to one of the versions above or updating your " \
                                f"install specifier to ensure a vulnerable version cannot be installed."


def get_specifier_range_info(style: bool = True, pin_hint: bool = False) -> str:
    """
    Get the specifier range information.

    Args:
        style (bool, optional): Whether to apply styling. Defaults to True.
        pin_hint (bool, optional): Whether to include a pin hint. Defaults to False.

    Returns:
        str: The specifier range information.
    """
    hint = ''

    if pin_hint:
        hint = 'It is recommended to pin your dependencies unless this is a library meant for distribution. '

    msg = f'{hint}To learn more about reporting these, specifier range handling, and options for scanning unpinned' \
          f' packages visit'
    link = 'https://docs.pyup.io/docs/safety-range-specs'

    if style:
        msg = click.style(msg, bold=True)

    return f'{msg} {link}'


def build_other_options_msg(fix_version: Optional[str], is_spec: bool, secure_options: List[str]) -> str:
    """
    Build the message for other secure options.

    Args:
        fix_version (Optional[str]): The recommended fix version.
        is_spec (bool): Whether the package is specified.
        secure_options (List[str]): List of secure options.

    Returns:
        str: The message for other secure options.
    """
    other_options_msg = ''
    raw_pre_other_options = ''
    outside = ''

    if fix_version:
        raw_pre_other_options = 'other '
    elif is_spec:
        outside = 'outside of your current specified range '

    if secure_options:
        if len(secure_options) == 1:
            raw_pre_other_options += f'version without known vulnerabilities {outside}is'
        else:
            raw_pre_other_options += f'versions without known vulnerabilities {outside}are:'

        other_options_msg = f"{raw_pre_other_options} {', '.join(secure_options)}".capitalize()

    return other_options_msg


def build_remediation_section(remediations: Dict[str, Any], only_text: bool = False, columns: int = get_terminal_size().columns, kwargs: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Build the remediation section content.

    Args:
        remediations (Dict[str, Any]): The remediations details.
        only_text (bool, optional): Whether to return only text without styling. Defaults to False.
        columns (int, optional): Number of columns for formatting. Defaults to terminal size.
        kwargs (Optional[Dict[str, Any]], optional): Additional arguments for formatting. Defaults to None.

    Returns:
        List[str]: The remediation section content.
    """
    columns -= 2
    indent = ' ' * 3

    if not kwargs:
        # Reset default params in the format_long_text func
        kwargs = {'indent': indent, 'columns': columns, 'start_line_decorator': '', 'end_line_decorator': '',
                  'sub_indent': indent}

    END_SECTION = '+' + '=' * columns + '+'

    if not remediations:
        return []

    content = ''
    total_vulns = 0
    total_packages = len(remediations.keys())

    for pkg in remediations.keys():
        for req, rem in remediations[pkg].items():
            total_vulns += rem['vulnerabilities_found']
            version = rem['version']
            spec = rem['requirement']
            is_spec = not version and spec
            secure_options: List[str] = [str(fix) for fix in rem.get('other_recommended_versions', [])]

            fix_version = None
            new_line = '\n'
            spec_info = []

            vuln_word = 'vulnerability'
            pronoun_word = 'this'

            if rem['vulnerabilities_found'] > 1:
                vuln_word = 'vulnerabilities'
                pronoun_word = 'these'

            if rem.get('recommended_version', None):
                fix_version = str(rem.get('recommended_version'))

            other_options_msg = build_other_options_msg(fix_version=fix_version, is_spec=is_spec,
                                                        secure_options=secure_options)

            spec_hint = ''

            if secure_options or fix_version and is_spec:
                raw_spec_info = get_unpinned_hint(pkg)

                spec_hint = f"{click.style(raw_spec_info, bold=True, fg='green')}" \
                            f" {get_specifier_range_info()}"

            if fix_version:
                fix_v: str = click.style(fix_version, bold=True)
                closest_msg = f'The closest version with no known vulnerabilities is {fix_v}'

                if is_spec:
                    closest_msg = f'Version {fix_v} has no known vulnerabilities and falls within your current specifier ' \
                                  f'range'

                raw_recommendation = f"We recommend updating to version {fix_version} of {pkg}."

                remediation_styled = click.style(f'{raw_recommendation} {other_options_msg}', bold=True,
                                                 fg='green')

                # Spec case
                if is_spec:
                    closest_msg += f'. {other_options_msg}'
                    remediation_styled = spec_hint

                remediation_content = [
                    closest_msg,
                    new_line,
                    remediation_styled
                ]

            else:
                no_known_fix_msg = f'There is no known fix for {pronoun_word} {vuln_word}.'

                if is_spec and secure_options:
                    no_known_fix_msg = f'There is no known fix for {pronoun_word} {vuln_word} in the current specified ' \
                                       f'range ({spec}).'

                no_fix_msg_styled = f"{click.style(no_known_fix_msg, bold=True, fg='yellow')} " \
                                    f"{click.style(other_options_msg, bold=True, fg='green')}"

                remediation_content = [new_line, no_fix_msg_styled]

                if spec_hint:
                    remediation_content.extend([new_line, spec_hint])

            # Pinned
            raw_rem_title = f"-> {pkg} version {version} was found, " \
                            f"which has {rem['vulnerabilities_found']} {vuln_word}"

            # Range
            if is_spec:
                # Spec remediation copy
                raw_rem_title = f"-> {pkg} with install specifier {spec} was found, " \
                                f"which has {rem['vulnerabilities_found']} {vuln_word}"

            remediation_title = click.style(raw_rem_title, fg=RED, bold=True)
            content += new_line + format_long_text(remediation_title,
                                                   **{**kwargs, **{'indent': '', 'sub_indent': ' ' * 3}}) + new_line

            pre_content = remediation_content + spec_info + [new_line,
                                                             f"For more information about the {pkg} package and update "
                                                             f"options, visit {rem['more_info_url']}",
                                                             f'Always check for breaking changes when updating packages.',
                                                             new_line]

            for i, element in enumerate(pre_content):
                content += format_long_text(element, **kwargs)

                if i + 1 < len(pre_content):
                    content += '\n'

    title = format_long_text(click.style('REMEDIATIONS', fg='green', bold=True), **kwargs)

    body = [content]

    if not is_using_api_key():
        vuln_text = 'vulnerabilities were' if total_vulns != 1 else 'vulnerability was'
        pkg_text = 'packages' if total_packages > 1 else 'package'
        msg = "{0} {1} reported in {2} {3}. " \
              "For detailed remediation & fix recommendations, upgrade to a commercial license."\
            .format(total_vulns, vuln_text, total_packages, pkg_text)
        content = '\n' + format_long_text(msg, indent=' ', sub_indent=' ', columns=columns) + '\n'
        body = [content]

    body.append(END_SECTION)

    content = [title] + body

    if only_text:
        content = [click.unstyle(item) for item in content]

    return content


def get_final_brief(total_vulns_found: int, remediations: Dict[str, Any], ignored: Dict[str, Any], total_ignored: int, kwargs: Optional[Dict[str, Any]] = None) -> str:
    """
    Get the final brief summary.

    Args:
        total_vulns_found (int): Total vulnerabilities found.
        remediations (Dict[str, Any]): Remediation details.
        ignored (Dict[str, Any]): Ignored vulnerabilities details.
        total_ignored (int): Total ignored vulnerabilities.
        kwargs (Optional[Dict[str, Any]], optional): Additional arguments for formatting. Defaults to None.

    Returns:
        str: Final brief summary.
    """
    if not kwargs:
        kwargs = {}

    rem_count: int = get_remediations_count(remediations)
    total_vulns = max(0, total_vulns_found - total_ignored)

    vuln_text = 'vulnerabilities' if total_ignored > 1 else 'vulnerability'
    pkg_text = 'packages were' if len(ignored.keys()) > 1 else 'package was'

    policy_file_text = ' using a safety policy file' if is_using_a_safety_policy_file() else ''

    vuln_brief = f" {total_vulns} vulnerabilit{'y was' if total_vulns == 1 else 'ies were'} reported."
    ignored_text = f' {total_ignored} {vuln_text} from {len(ignored.keys())} {pkg_text} ignored.' if ignored else ''
    remediation_text = f" {rem_count} remediation{' was' if rem_count == 1 else 's were'} " \
                       f"recommended." if is_using_api_key() else ''

    raw_brief = f"Scan was completed{policy_file_text}.{vuln_brief}{ignored_text}{remediation_text}"

    return format_long_text(raw_brief, start_line_decorator=' ', **kwargs)


def get_final_brief_license(licenses: List[str], kwargs: Optional[Dict[str, Any]] = None) -> str:
    """
    Get the final brief summary for licenses.

    Args:
        licenses (List[str]): List of licenses.
        kwargs (Optional[Dict[str, Any]], optional): Additional arguments for formatting. Defaults to None.

    Returns:
        str: Final brief summary for licenses.
    """
    if not kwargs:
        kwargs = {}

    licenses_text = ' Scan was completed.'

    if licenses:
        licenses_text = 'The following software licenses were present in your system: {0}'.format(', '.join(licenses))

    return format_long_text("{0}".format(licenses_text), start_line_decorator=' ', **kwargs)


def format_long_text(text: str, color: str = '', columns: int = get_terminal_size().columns, start_line_decorator: str = ' ', end_line_decorator: str = ' ', max_lines: Optional[int] = None, styling: Optional[Dict[str, Any]] = None, indent: str = '', sub_indent: str = '') -> str:
    """
    Format long text with wrapping and styling.

    Args:
        text (str): The text to format.
        color (str, optional): Color for the text. Defaults to ''.
        columns (int, optional): Number of columns for formatting. Defaults to terminal size.
        start_line_decorator (str, optional): Starting line decorator. Defaults to ' '.
        end_line_decorator (str, optional): Ending line decorator. Defaults to ' '.
        max_lines (Optional[int], optional): Maximum number of lines. Defaults to None.
        styling (Optional[Dict[str, Any]], optional): Additional styling options. Defaults to None.
        indent (str, optional): Indentation for the text. Defaults to ''.
        sub_indent (str, optional): Sub-indentation for the text. Defaults to ''.

    Returns:
        str: Formatted text.
    """
    if not styling:
        styling = {}

    if color:
        styling.update({'fg': color})

    columns -= len(start_line_decorator) + len(end_line_decorator)
    formatted_lines = []
    lines = text.replace('\r', '').splitlines()

    for line in lines:
        base_format = "{:" + str(columns) + "}"
        if line == '':
            empty_line = base_format.format(" ")
            formatted_lines.append("{0}{1}{2}".format(start_line_decorator, empty_line, end_line_decorator))
        wrapped_lines = textwrap.wrap(line, width=columns, max_lines=max_lines, initial_indent=indent,
                                      subsequent_indent=sub_indent, placeholder='...')
        for wrapped_line in wrapped_lines:
            new_line = f'{wrapped_line}'

            if styling:
                new_line = click.style(new_line, **styling)

            formatted_lines.append(f"{start_line_decorator}{new_line}{end_line_decorator}")

    return "\n".join(formatted_lines)


def get_printable_list_of_scanned_items(scanning_target: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Get a printable list of scanned items.

    Args:
        scanning_target (str): The scanning target (environment, stdin, files, or file).

    Returns:
        Tuple[List[Dict[str, Any]], List[str]]: Printable list of scanned items and scanned items data.
    """
    context = SafetyContext()

    result = []
    scanned_items_data = []

    if scanning_target == 'environment':
        locations = set(SafetyContext().scanned_full_path)

        for path in locations:
            result.append([{'styled': False, 'value': '-> ' + path}])
            scanned_items_data.append(path)

        if len(locations) <= 0:
            msg = 'No locations found in the environment'
            result.append([{'styled': False, 'value': msg}])
            scanned_items_data.append(msg)

    elif scanning_target == 'stdin':
        scanned_stdin = [pkg.name for pkg in context.packages if isinstance(pkg, Package)]
        value = 'No found packages in stdin'
        scanned_items_data = [value]

        if len(scanned_stdin) > 0:
            value = ', '.join(scanned_stdin)
            scanned_items_data = scanned_stdin

        result.append(
            [{'styled': False, 'value': value}])

    elif scanning_target == 'files':
        for file in context.params.get('files', []):
            result.append([{'styled': False, 'value': f'-> {file.name}'}])
            scanned_items_data.append(file.name)
    elif scanning_target == 'file':
        file = context.params.get('file', None)
        name = file.name if file else ''
        result.append([{'styled': False, 'value': f'-> {name}'}])
        scanned_items_data.append(name)

    return result, scanned_items_data


REPORT_HEADING = format_long_text(click.style('REPORT', bold=True))


def build_report_brief_section(columns: Optional[int] = None, primary_announcement: Optional[Dict[str, Any]] = None, report_type: int = 1, **kwargs: Any) -> str:
    """
    Build the brief section of the report.

    Args:
        columns (Optional[int], optional): Number of columns for formatting. Defaults to None.
        primary_announcement (Optional[Dict[str, Any]], optional): Primary announcement details. Defaults to None.
        report_type (int, optional): Type of the report. Defaults to 1.
        **kwargs: Additional arguments for formatting.

    Returns:
        str: Brief section of the report.
    """
    if not columns:
        columns = get_terminal_size().columns

    styled_brief_lines = []

    if primary_announcement:
        styled_brief_lines.append(
            build_primary_announcement(columns=columns, primary_announcement=primary_announcement))

    for line in get_report_brief_info(report_type=report_type, **kwargs):
        ln = ''
        padding = ' ' * 2

        for i, words in enumerate(line):
            processed_words = words.get('value', '')
            if words.get('style', False):
                text = ''
                if i == 0:
                    text = padding
                    padding = ''
                text += processed_words

                processed_words = click.style(text, bold=True)

            ln += processed_words

        styled_brief_lines.append(format_long_text(ln, color='', columns=columns, start_line_decorator='',
                                                   indent=padding, end_line_decorator='', sub_indent=' ' * 2))

    return "\n".join([add_empty_line(), REPORT_HEADING, add_empty_line(), '\n'.join(styled_brief_lines)])


def build_report_for_review_vuln_report(as_dict: bool = False) -> Union[Dict[str, Any], List[List[Dict[str, Any]]]]:
    """
    Build the report for review vulnerability report.

    Args:
        as_dict (bool, optional): Whether to return as a dictionary. Defaults to False.

    Returns:
        Union[Dict[str, Any], List[List[Dict[str, Any]]]]: Review vulnerability report.
    """
    ctx = SafetyContext()
    report_from_file = ctx.review
    packages = ctx.packages

    if as_dict:
        return report_from_file

    policy_f_name = report_from_file.get('policy_file', None)
    safety_policy_used = []
    if policy_f_name:
        safety_policy_used = [
            {'style': False, 'value': '\nScanning using a security policy file'},
            {'style': True, 'value': ' {0}'.format(policy_f_name)},
        ]

    action_executed = [
        {'style': True, 'value': 'Scanning dependencies'},
        {'style': False, 'value': ' in your '},
        {'style': True, 'value': report_from_file.get('scan_target', '-') + ':'},
        ]

    scanned_items = []

    for name in report_from_file.get('scanned', []):
        scanned_items.append([{'styled': False, 'value': '-> ' + name}])

    nl = [{'style': False, 'value': ''}]
    using_sentence = build_using_sentence(None,
                                          report_from_file.get('api_key', None),
                                          report_from_file.get('local_database_path_used', None))
    scanned_count_sentence = build_scanned_count_sentence(packages)
    old_timestamp = report_from_file.get('timestamp', None)

    old_timestamp = [{'style': False, 'value': 'Report generated '}, {'style': True, 'value': old_timestamp}]
    now = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    current_timestamp = [{'style': False, 'value': 'Timestamp '}, {'style': True, 'value': now}]

    brief_info = [[{'style': False, 'value': 'Safety '},
     {'style': True, 'value': 'v' + report_from_file.get('safety_version', '-')},
     {'style': False, 'value': ' is scanning for '},
     {'style': True, 'value': 'Vulnerabilities'},
     {'style': True, 'value': '...'}] + safety_policy_used, action_executed
     ] + [nl] + scanned_items + [nl] + [using_sentence] + [scanned_count_sentence] + [old_timestamp] + \
                 [current_timestamp]

    return brief_info


def build_using_sentence(account: Optional[str], key: Optional[str], db: Optional[str]) -> List[Dict[str, Any]]:
    """
    Build the sentence for the used components.

    Args:
        account (Optional[str]): The account details.
        key (Optional[str]): The API key.
        db (Optional[str]): The database details.

    Returns:
        List[Dict[str, Any]]: Sentence for the used components.
    """
    key_sentence = []
    custom_integration = os.environ.get('SAFETY_CUSTOM_INTEGRATION',
                                        'false').lower() == 'true'

    if key or account:
        t = {'style': True, 'value': 'an API KEY'}
        if not key:
            t = {'style': True, 'value': f'the account {account}'}
        key_sentence = [t,
                        {'style': False, 'value': ' and the '}]
        db_name = 'Safety Commercial'
    elif db:
        if is_a_remote_mirror(db):
            if custom_integration:
                return []
            db_name = f"remote URL {db}"
        else:
            db_name = f"local file {db}"
    else:
        db_name = 'open-source vulnerability'

    database_sentence = [{'style': True, 'value': db_name + ' database'}]

    return [{'style': False, 'value': 'Using '}] + key_sentence + database_sentence


def build_scanned_count_sentence(packages: List[Package]) -> List[Dict[str, Any]]:
    """
    Build the sentence for the scanned count.

    Args:
        packages (List[Package]): List of packages.

    Returns:
        List[Dict[str, Any]]: Sentence for the scanned count.
    """
    scanned_count = 'No packages found'
    if len(packages) >= 1:
        scanned_count = 'Found and scanned {0} {1}'.format(len(packages),
                                                           'packages' if len(packages) > 1 else 'package')

    return [{'style': True, 'value': scanned_count}]


def add_warnings_if_needed(brief_info: List[List[Dict[str, Any]]]):
    """
    Add warnings to the brief info if needed.

    Args:
        brief_info (List[List[Dict[str, Any]]]): Brief info details.
    """
    ctx = SafetyContext()
    warnings = []

    if ctx.packages:
        if ctx.params.get('continue_on_error', False):
            warnings += [[{'style': True,
                           'value': '* Continue-on-error is enabled, so returning successful (0) exit code in all cases.'}]]

        if ctx.params.get('ignore_severity_rules', False) and not is_using_api_key():
            warnings += [[{'style': True,
                           'value': '* Could not filter by severity, please upgrade your account to include severity data.'}]]

    if warnings:
        brief_info += [[{'style': False, 'value': ''}]] + warnings


def get_report_brief_info(as_dict: bool = False, report_type: int = 1, **kwargs: Any):
    """
    Get the brief info of the report.

    Args:
        as_dict (bool, optional): Whether to return as a dictionary. Defaults to False.
        report_type (int, optional): Type of the report. Defaults to 1.
        **kwargs: Additional arguments for the report.

    Returns:
        Union[Dict[str, Any], List[List[Dict[str, Any]]]]: Brief info of the report.
    """
    LOG.info('get_report_brief_info: %s, %s, %s', as_dict, report_type, kwargs)

    context = SafetyContext()

    packages = [pkg for pkg in context.packages if isinstance(pkg, Package)]
    brief_data = {}
    command = context.command

    if command == 'review':
        review = build_report_for_review_vuln_report(as_dict)
        return review

    account = context.account
    key = context.key
    db = context.db_mirror

    scanning_types = {'check': {'name': 'Vulnerabilities', 'action': 'Scanning dependencies', 'scanning_target': 'environment'}, # Files, Env or Stdin
                      'license': {'name': 'Licenses', 'action': 'Scanning licenses', 'scanning_target': 'environment'}, # Files or Env
                      'review': {'name': 'Report', 'action': 'Reading the report',
                                 'scanning_target': 'file'}} # From file

    targets = ['stdin', 'environment', 'files', 'file']
    for target in targets:
        if context.params.get(target, False):
            scanning_types[command]['scanning_target'] = target
            break

    scanning_target = scanning_types.get(context.command, {}).get('scanning_target', '')
    brief_data['scan_target'] = scanning_target
    scanned_items, data = get_printable_list_of_scanned_items(scanning_target)
    brief_data['scanned'] = data
    nl = [{'style': False, 'value': ''}]

    brief_data['scanned_full_path'] = SafetyContext().scanned_full_path
    brief_data['target_languages'] = ['python']

    action_executed = [
        {'style': True, 'value': scanning_types.get(context.command, {}).get('action', '')},
        {'style': False, 'value': ' in your '},
        {'style': True, 'value': scanning_target + ':'},
        ]

    policy_file = context.params.get('policy_file', None)
    safety_policy_used = []

    brief_data['policy_file'] = policy_file.get('filename', '-') if policy_file else None
    brief_data['policy_file_source'] = 'server' if brief_data['policy_file'] and 'server-safety-policy' in brief_data['policy_file'] else 'local'

    if policy_file and policy_file.get('filename', False):
        safety_policy_used = [
            {'style': False, 'value': '\nScan configuration using a security policy file'},
            {'style': True, 'value': ' {0}'.format(policy_file.get('filename', '-'))},
        ]

    audit_and_monitor = []
    if context.params.get('audit_and_monitor'):
        logged_url = context.params.get('audit_and_monitor_url') if context.params.get('audit_and_monitor_url') else "https://safetycli.com"
        audit_and_monitor = [
            {'style': False, 'value': '\nLogging scan results to'},
            {'style': True, 'value': ' {0}'.format(logged_url)},
        ]
        brief_data['audit_and_monitor'] = logged_url
    else:
        brief_data['audit_and_monitor'] = False


    current_time = str(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    brief_data['api_key'] = bool(key)
    brief_data['account'] = account
    brief_data['local_database_path'] = db if db else None
    brief_data['safety_version'] = get_version()
    brief_data['timestamp'] = current_time
    brief_data['packages_found'] = len(packages)
    # Vuln report
    additional_data = []
    if report_type == 1:
        brief_data['vulnerabilities_found'] = kwargs.get('vulnerabilities_found', 0)
        brief_data['vulnerabilities_ignored'] = kwargs.get('vulnerabilities_ignored', 0)
        brief_data['remediations_recommended'] = 0

        additional_data = [
            [{'style': True, 'value': str(brief_data['vulnerabilities_found'])},
             {'style': True, 'value': f' vulnerabilit{"y" if brief_data["vulnerabilities_found"] == 1 else "ies"} reported'}],
            [{'style': True, 'value': str(brief_data['vulnerabilities_ignored'])},
             {'style': True, 'value': f' vulnerabilit{"y" if brief_data["vulnerabilities_ignored"] == 1 else "ies"} ignored'}],
        ]

        if is_using_api_key():
            brief_data['remediations_recommended'] = get_remediations_count(kwargs.get('remediations_recommended', {}))
            additional_data.extend(
                [[{'style': True, 'value': str(brief_data['remediations_recommended'])},
                 {'style': True, 'value':
                     f' remediation{"" if brief_data["remediations_recommended"] == 1 else "s"} recommended'}]])

    elif report_type == 2:
        brief_data['licenses_found'] = kwargs.get('licenses_found', 0)
        additional_data = [
            [{'style': True, 'value': str(brief_data['licenses_found'])},
             {'style': True, 'value': f' license {"type" if brief_data["licenses_found"] == 1 else "types"} found'}],
        ]

    brief_data['telemetry'] = asdict(build_telemetry_data())

    brief_data['git'] = build_git_data()
    brief_data['project'] = context.params.get('project', None)

    brief_data['json_version'] = "1.1"

    using_sentence = build_using_sentence(account, key, db)
    sentence_array = []
    for section in using_sentence:
        sentence_array.append(section['value'])
    brief_using_sentence = ' '.join(sentence_array)
    brief_data['using_sentence'] = brief_using_sentence

    using_sentence_section = [nl] if not using_sentence else [nl] + [using_sentence]
    scanned_count_sentence = build_scanned_count_sentence(packages)

    timestamp = [{'style': False, 'value': 'Timestamp '}, {'style': True, 'value': current_time}]

    brief_info = [[{'style': False, 'value': 'Safety '},
     {'style': True, 'value': 'v' + get_version()},
     {'style': False, 'value': ' is scanning for '},
     {'style': True, 'value': scanning_types.get(context.command, {}).get('name', '')},
     {'style': True, 'value': '...'}] + safety_policy_used + audit_and_monitor, action_executed
     ] + [nl] + scanned_items + using_sentence_section + [scanned_count_sentence] + [timestamp]

    brief_info.extend(additional_data)

    add_warnings_if_needed(brief_info)

    LOG.info('Brief info data: %s', brief_data)
    LOG.info('Brief info, styled output: %s', '\n\n LINE ---->\n ' + '\n\n LINE ---->\n '.join(map(str, brief_info)))

    return brief_data if as_dict else brief_info


def build_primary_announcement(primary_announcement, columns: Optional[int] = None, only_text: bool = False) -> str:
    """
    Build the primary announcement section.

    Args:
        primary_announcement (Dict[str, Any]): Primary announcement details.
        columns (Optional[int], optional): Number of columns for formatting. Defaults to None.
        only_text (bool, optional): Whether to return only text without styling. Defaults to False.

    Returns:
        str: Primary announcement section.
    """
    lines = json.loads(primary_announcement.get('message'))

    for line in lines:
        if 'words' not in line:
            raise ValueError('Missing words keyword')
        if len(line['words']) <= 0:
            raise ValueError('No words in this line')
        for word in line['words']:
            if 'value' not in word or not word['value']:
                raise ValueError('Empty word or without value')

    message = style_lines(lines, columns, start_line='', end_line='')

    return click.unstyle(message) if only_text else message


def is_using_api_key() -> bool:
    """
    Check if an API key is being used.

    Returns:
        bool: True if using an API key, False otherwise.
    """
    return bool(SafetyContext().key) or bool(SafetyContext().account)


def is_using_a_safety_policy_file() -> bool:
    """
    Check if a safety policy file is being used.

    Returns:
        bool: True if using a safety policy file, False otherwise.
    """
    return bool(SafetyContext().params.get('policy_file', None))


def should_add_nl(output: str, found_vulns: bool) -> bool:
    """
    Determine if a newline should be added.

    Args:
        output (str): The output format.
        found_vulns (bool): Whether vulnerabilities were found.

    Returns:
        bool: True if a newline should be added, False otherwise.
    """
    if output == 'bare' and not found_vulns:
        return False

    return True


def get_skip_reason(fix: Fix) -> str:
    """
    Get the reason for skipping a fix.

    Args:
        fix (Fix): The fix details.

    Returns:
        str: The reason for skipping the fix.
    """
    range_msg = ''

    if not fix.updated_version and fix.other_options:
        range_msg = f' in your current install range ({fix.previous_spec}). Please read the remediation output ' \
                    f'for more details and how to update this spec'

    reasons = {"AUTOMATICALLY_SKIPPED_NO_RECOMMENDED_VERSION": f"there is no secure version{range_msg}.",
               "MANUALLY_SKIPPED": "it was manually discarded.",
               "AUTOMATICALLY_SKIPPED_UNABLE_TO_CONFIRM": "not able to confirm."
               }

    return reasons.get(fix.status, 'unknown.')


def get_applied_msg(fix: Fix, mode: str = "auto") -> str:
    """
    Get the message for an applied fix.

    Args:
        fix (Fix): The fix details.
        mode (str, optional): The mode of the fix. Defaults to "auto".

    Returns:
        str: The message for the applied fix.
    """
    return f"{fix.package}{fix.previous_spec} has a {fix.update_type} version fix available: {mode} updating to =={fix.updated_version}."


def get_skipped_msg(fix: Fix) -> str:
    """
    Get the message for a skipped fix.

    Args:
        fix (Fix): The fix details.

    Returns:
        str: The message for the skipped fix.
    """
    return f'{fix.package} remediation was skipped because {get_skip_reason(fix)}'


def get_fix_opt_used_msg(fix_options: Optional[List[str]] = None) -> str:
    """
    Get the message for the fix options used.

    Args:
        fix_options (Optional[List[str]], optional): The fix options. Defaults to None.

    Returns:
        str: The message for the fix options used.
    """

    if not fix_options:
        fix_options = SafetyContext().params.get('auto_remediation_limit', [])

    msg = "no automatic"

    if fix_options:
        msg = f"automatic {', '.join(fix_options)} update"

    if SafetyContext().params.get('accept_all', False):
        msg += ' and force'

    return msg


def print_service(output: List[Tuple[str, Dict[str, Any]]], out_format: str, format_text: Optional[Dict[str, Any]] = None):
    """
    Print the service output.

    Args:
        output (List[Tuple[str, Dict[str, Any]]]): The output to print.
        out_format (str): The output format.
        format_text (Optional[Dict[str, Any]], optional): Additional text formatting options. Defaults to None.

    Raises:
        ValueError: If the output format is not allowed.
    """
    formats = ['text', 'screen']

    if out_format not in formats:
        raise ValueError(f"Print is only allowed for {', '.join(formats)}")

    if not format_text:
        format_text = {'start_line_decorator': '', 'sub_indent': ' ' * 5, 'indent': ' ' * 3}
        if out_format == 'text':
            format_text['columns'] = 80

    while output:
        line, kwargs = output.pop(0)
        line = format_long_text(line, **{**format_text, **kwargs})

        if out_format == 'screen':
            click.secho(line)
        else:
            click.echo(click.unstyle(line))



def prompt_service(output: Tuple[str, Dict[str, Any]], out_format: str, format_text: Optional[Dict[str, Any]] = None) -> bool:
    """
    Prompt the user for input.

    Args:
        output (Tuple[str, Dict[str, Any]]): The output to display.
        out_format (str): The output format.
        format_text (Optional[Dict[str, Any]], optional): Additional text formatting options. Defaults to None.

    Returns:
        bool: The user response.

    Raises:
        ValueError: If the output format is not allowed.
    """
    formats = ['text', 'screen']

    if out_format not in formats:
        raise ValueError(f"Prompt is only allowed for {', '.join(formats)}")

    if not format_text:
        format_text = {'start_line_decorator': '', 'sub_indent': ' ' * 5, 'indent': ' ' * 3}
        if out_format == 'text':
            format_text['columns'] = 80

    line, kwargs = output
    msg = format_long_text(line, **{**format_text, **kwargs})

    if out_format == 'text':
        msg = click.unstyle(msg)

    return click.prompt(msg)


def parse_html(*, kwargs: Dict[str, Any], template: str = 'index.html') -> str:
    """
    Parse HTML using Jinja2 templates.

    Args:
        kwargs (Dict[str, Any]): The template variables.
        template (str, optional): The template name. Defaults to 'index.html'.

    Returns:
        str: The rendered HTML.
    """
    file_loader = PackageLoader('safety', 'templates')
    env = Environment(loader=file_loader)
    template = env.get_template(template)
    return template.render(**kwargs)


def format_unpinned_vulnerabilities(unpinned_packages: Dict[str, List[Any]], columns: Optional[int] = None) -> List[str]:
    """
    Format unpinned vulnerabilities.

    Args:
        unpinned_packages (Dict[str, List[Any]]): Unpinned packages and their vulnerabilities.
        columns (Optional[int], optional): Number of columns for formatting. Defaults to None.

    Returns:
        List[str]: Formatted unpinned vulnerabilities.
    """
    lines = []

    if not unpinned_packages:
        return lines

    for pkg_name, vulns in unpinned_packages.items():
        total = {vuln.vulnerability_id for vuln in vulns}
        pkg = vulns[0].pkg
        doc_msg: str = get_specifier_range_info(style=False, pin_hint=True)

        match_text = 'vulnerabilities match' if len(total) > 1 else 'vulnerability matches'
        reqs = ', '.join([str(r) for r in pkg.get_unpinned_req()])

        msg = f"-> Warning: {len(total)} known {match_text} the {pkg.name} versions that could be " \
              f"installed from your specifier{'s' if len(pkg.requirements) > 1 else ''}: {reqs} (unpinned). These vulnerabilities are not " \
              f"reported by default. To report these vulnerabilities set 'ignore-unpinned-requirements' to False " \
              f"under 'security' in your policy file. " \
              f"See https://docs.pyup.io/docs/safety-20-policy-file for more information."

        kwargs = {'color': 'yellow', 'indent': '', 'sub_indent': ' ' * 3, 'start_line_decorator': '',
                  'end_line_decorator': ' '}

        if columns:
            kwargs.update({'columns': columns})

        msg = format_long_text(text=msg, **kwargs)
        doc_msg = format_long_text(text=doc_msg, **{**kwargs, **{'indent': ' ' * 3}})

        lines.append(f'{msg}\n{doc_msg}')

    return lines
