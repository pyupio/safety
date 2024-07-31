import hashlib
import os
import sys
from functools import wraps
from typing import Optional, List, Dict, Any

from packaging.version import parse as parse_version
from packaging.specifiers import SpecifierSet
from pathlib import Path

import click

# Jinja2 will only be installed if the optional deps are installed.
# It's fine if our functions fail, but don't let this top level
# import error out.
from safety.models import is_pinned_requirement
from safety.output_utils import get_unpinned_hint, get_specifier_range_info, get_fix_hint_for_unpinned

try:
    import jinja2
except ImportError:
    jinja2 = None

import requests


def highest_base_score(vulns: List[Dict[str, Any]]) -> float:
    """
    Calculates the highest CVSS base score from a list of vulnerabilities.

    Args:
        vulns (List[Dict[str, Any]]): The list of vulnerabilities.

    Returns:
        float: The highest CVSS base score.
    """
    highest_base_score = 0
    for vuln in vulns:
        if vuln['severity'] is not None:
            highest_base_score = max(highest_base_score, (vuln['severity'].get('cvssv3', {}) or {}).get('base_score', 10))

    return highest_base_score


def generate_branch_name(pkg: str, remediation: Dict[str, Any]) -> str:
    """
    Generates a branch name for a given package and remediation.

    Args:
        pkg (str): The package name.
        remediation (Dict[str, Any]): The remediation data.

    Returns:
        str: The generated branch name.
    """
    return f"{pkg}/{remediation['requirement']['specifier']}/{remediation['recommended_version']}"


def generate_issue_title(pkg: str, remediation: Dict[str, Any]) -> str:
    """
    Generates an issue title for a given package and remediation.

    Args:
        pkg (str): The package name.
        remediation (Dict[str, Any]): The remediation data.

    Returns:
        str: The generated issue title.
    """
    return f"Security Vulnerability in {pkg}{remediation['requirement']['specifier']}"


def get_hint(remediation: Dict[str, Any]) -> str:
    """
    Generates a hint for a given remediation.

    Args:
        remediation (Dict[str, Any]): The remediation data.

    Returns:
        str: The generated hint.
    """
    pinned = is_pinned_requirement(SpecifierSet(remediation['requirement']['specifier']))
    hint = ''

    if not pinned:
        fix_hint = get_fix_hint_for_unpinned(remediation)
        hint = f"{fix_hint}\n\n{get_unpinned_hint(remediation['requirement']['name'])} " \
               f"{get_specifier_range_info(style=False)}"

    return hint


def generate_title(pkg: str, remediation: Dict[str, Any], vulns: List[Dict[str, Any]]) -> str:
    """
    Generates a title for a pull request or issue.

    Args:
        pkg (str): The package name.
        remediation (Dict[str, Any]): The remediation data.
        vulns (List[Dict[str, Any]]): The list of vulnerabilities.

    Returns:
        str: The generated title.
    """
    suffix = "y" if len(vulns) == 1 else "ies"
    from_dependency = remediation['version'] if remediation['version'] else remediation['requirement']['specifier']
    return f"Update {pkg} from {from_dependency} to {remediation['recommended_version']} to fix {len(vulns)} vulnerabilit{suffix}"


def generate_body(pkg: str, remediation: Dict[str, Any], vulns: List[Dict[str, Any]], *, api_key: str) -> Optional[str]:
    """
    Generates the body content for a pull request.

    Args:
        pkg (str): The package name.
        remediation (Dict[str, Any]): The remediation data.
        vulns (List[Dict[str, Any]]): The list of vulnerabilities.
        api_key (str): The API key for fetching changelog data.

    Returns:
        str: The generated body content.
    """
    changelog = fetch_changelog(pkg, remediation['version'], remediation['recommended_version'],
                                api_key=api_key, from_spec=remediation.get('requirement', {}).get('specifier', None))

    p = Path(__file__).parent / 'templates'
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(Path(p)))
    template = env.get_template('pr.jinja2')

    overall_impact = cvss3_score_to_label(highest_base_score(vulns))

    context = {"pkg": pkg, "remediation": remediation, "vulns": vulns, "changelog": changelog,
               "overall_impact": overall_impact, "summary_changelog": False, "hint": get_hint(remediation)}

    result = template.render(context)

    # GitHub has a PR body length limit of 65536. If we're going over that, skip the changelog and just use a link.
    if len(result) < 65500:
        return result

    context["summary_changelog"] = True

    return template.render(context)


def generate_issue_body(pkg: str, remediation: Dict[str, Any], vulns: List[Dict[str, Any]], *, api_key: str) -> Optional[str]:
    """
    Generates the body content for an issue.

    Args:
        pkg (str): The package name.
        remediation (Dict[str, Any]): The remediation data.
        vulns (List[Dict[str, Any]]): The list of vulnerabilities.
        api_key (str): The API key for fetching changelog data.

    Returns:
        str: The generated body content.
    """
    changelog = fetch_changelog(pkg, remediation['version'], remediation['recommended_version'],
                                api_key=api_key, from_spec=remediation.get('requirement', {}).get('specifier', None))

    p = Path(__file__).parent / 'templates'
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(Path(p)))
    template = env.get_template('issue.jinja2')

    overall_impact = cvss3_score_to_label(highest_base_score(vulns))

    context = {"pkg": pkg, "remediation": remediation, "vulns": vulns, "changelog": changelog,
               "overall_impact": overall_impact, "summary_changelog": False, "hint": get_hint(remediation)}

    result = template.render(context)

    # GitHub has a PR body length limit of 65536. If we're going over that, skip the changelog and just use a link.
    if len(result) < 65500:
        return result

    context["summary_changelog"] = True

    return template.render(context)


def generate_commit_message(pkg: str, remediation: Dict[str, Any]) -> str:
    """
    Generates a commit message for a given package and remediation.

    Args:
        pkg (str): The package name.
        remediation (Dict[str, Any]): The remediation data.

    Returns:
        str: The generated commit message.
    """
    from_dependency = remediation['version'] if remediation['version'] else remediation['requirement']['specifier']

    return f"Update {pkg} from {from_dependency} to {remediation['recommended_version']}"


def git_sha1(raw_contents: bytes) -> str:
    """
    Calculates the SHA-1 hash of the given raw contents.

    Args:
        raw_contents (bytes): The raw contents to hash.

    Returns:
        str: The SHA-1 hash.
    """
    return hashlib.sha1(b"blob " + str(len(raw_contents)).encode('ascii') + b"\0" + raw_contents).hexdigest()


def fetch_changelog(package: str, from_version: Optional[str], to_version: str, *, api_key: str, from_spec: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetches the changelog for a package from a specified version to another version.

    Args:
        package (str): The package name.
        from_version (Optional[str]): The starting version.
        to_version (str): The ending version.
        api_key (str): The API key for fetching changelog data.
        from_spec (Optional[str]): The specifier for the starting version.

    Returns:
        Dict[str, Any]: The fetched changelog data.
    """
    to_version = parse_version(to_version)

    if from_version:
        from_version = parse_version(from_version)
    else:
        from_spec = SpecifierSet(from_spec)

    changelog = {}

    r = requests.get(
        "https://pyup.io/api/v1/changelogs/{}/".format(package),
        headers={"X-Api-Key": api_key}
    )

    if r.status_code == 200:
        data = r.json()
        if data:
            # sort the changelog by release
            sorted_log = sorted(data.items(), key=lambda v: parse_version(v[0]), reverse=True)

            # go over each release and add it to the log if it's within the "upgrade
            # range" e.g. update from 1.2 to 1.3 includes a changelog for 1.2.1 but
            # not for 0.4.
            for version, log in sorted_log:
                parsed_version = parse_version(version)
                version_check = from_version and (parsed_version > from_version)
                spec_check = from_spec and isinstance(from_spec, SpecifierSet) and from_spec.contains(parsed_version)

                if version_check or spec_check and parsed_version <= to_version:
                    changelog[version] = log

    return changelog


def cvss3_score_to_label(score: float) -> Optional[str]:
    """
    Converts a CVSS v3 score to a severity label.

    Args:
        score (float): The CVSS v3 score.

    Returns:
        Optional[str]: The severity label.
    """
    if 0.1 <= score <= 3.9:
        return 'low'
    elif 4.0 <= score <= 6.9:
        return 'medium'
    elif 7.0 <= score <= 8.9:
        return 'high'
    elif 9.0 <= score <= 10.0:
        return 'critical'

    return None


def require_files_report(func):
    @wraps(func)
    def inner(obj: Any, *args: Any, **kwargs: Any) -> Any:
        """
        Decorator that ensures a report is generated against a file.

        Args:
            obj (Any): The object containing the report.
            *args (Any): Additional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            Any: The result of the decorated function.
        """
        if obj.report['report_meta']['scan_target'] != "files":
            click.secho("This report was generated against an environment, but this alert command requires "
                        "a scan report that was generated against a file. To learn more about the "
                        "`safety alert` command visit https://docs.pyup.io/docs/safety-2-alerts", fg='red')
            sys.exit(1)

        files = obj.report['report_meta']['scanned']
        obj.requirements_files = {}
        for f in files:
            if not os.path.exists(f):
                cwd = os.getcwd()
                click.secho("A requirements file scanned in the report, {}, does not exist (looking in {}).".format(f, cwd), fg='red')
                sys.exit(1)

            obj.requirements_files[f] = open(f, "rb").read()

        return func(obj, *args, **kwargs)
    return inner
