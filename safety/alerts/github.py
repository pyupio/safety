# type: ignore
import itertools
import logging
import re
import sys
from typing import Any, Optional

import click

try:
    import github as pygithub
except ImportError:
    pygithub = None

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from . import utils, requirements

LOG = logging.getLogger(__name__)


def create_branch(repo: Any, base_branch: str, new_branch: str) -> None:
    """
    Create a new branch in the given GitHub repository.

    Args:
        repo (Any): The GitHub repository object.
        base_branch (str): The name of the base branch.
        new_branch (str): The name of the new branch to create.
    """
    ref = repo.get_git_ref("heads/" + base_branch)
    repo.create_git_ref(ref="refs/heads/" + new_branch, sha=ref.object.sha)


def delete_branch(repo: Any, branch: str) -> None:
    """
    Delete a branch from the given GitHub repository.

    Args:
        repo (Any): The GitHub repository object.
        branch (str): The name of the branch to delete.
    """
    ref = repo.get_git_ref(f"heads/{branch}")
    ref.delete()


@click.command()
@click.option("--repo", help="GitHub standard repo path (eg, my-org/my-project)")
@click.option("--token", help="GitHub Access Token")
@click.option(
    "--base-url",
    help="Optional custom Base URL, if you're using GitHub enterprise",
    default=None,
)
@click.pass_obj
@utils.require_files_report
def github_pr(obj: Any, repo: str, token: str, base_url: Optional[str]) -> None:
    """
    Create a GitHub PR to fix any vulnerabilities using Safety's remediation data.

    This is usually run by a GitHub action. If you're running this manually, ensure that your local repo is up to date and on HEAD - otherwise you'll see strange results.

    Args:
        obj (Any): The Click context object containing report data.
        repo (str): The GitHub repository path.
        token (str): The GitHub Access Token.
        base_url (Optional[str]): Custom base URL for GitHub Enterprise, if applicable.
    """
    if pygithub is None:
        click.secho(
            "pygithub is not installed. Did you install Safety with GitHub support? Try pip install safety[github]",
            fg="red",
        )
        sys.exit(1)

    # Load alert configurations from the policy
    alert = obj.policy.get("alert", {}) or {}
    security = alert.get("security", {}) or {}
    config_pr = security.get("github-pr", {}) or {}

    branch_prefix = config_pr.get("branch-prefix", "pyup/")
    pr_prefix = config_pr.get("pr-prefix", "[PyUp] ")
    assignees = config_pr.get("assignees", [])
    labels = config_pr.get("labels", ["security"])
    label_severity = config_pr.get("label-severity", True)
    ignore_cvss_severity_below = config_pr.get("ignore-cvss-severity-below", 0)
    ignore_cvss_unknown_severity = config_pr.get("ignore-cvss-unknown-severity", False)

    # Authenticate with GitHub
    gh = pygithub.Github(token, **({"base_url": base_url} if base_url else {}))
    repo_name = repo
    repo = gh.get_repo(repo)
    try:
        self_user = gh.get_user().login
    except pygithub.GithubException:
        # If we're using a token from an action (or integration) we can't call `get_user()`. Fall back
        # to assuming we're running under an action
        self_user = "web-flow"

    # Collect all remediations from the report
    req_remediations = list(
        itertools.chain.from_iterable(
            rem.get("requirements", {}).values()
            for pkg_name, rem in obj.report["remediations"].items()
        )
    )

    # Get all open pull requests for the repository
    pulls = repo.get_pulls(state="open", sort="created", base=repo.default_branch)
    pending_updates = set(
        [
            f"{canonicalize_name(req_rem['requirement']['name'])}{req_rem['requirement']['specifier']}"
            for req_rem in req_remediations
        ]
    )

    created = 0

    # TODO: Refactor this loop into a fn to iterate over remediations nicely
    # Iterate over all requirements files and process each remediation
    for name, contents in obj.requirements_files.items():
        raw_contents = contents
        contents = contents.decode("utf-8")  # TODO - encoding?
        parsed_req_file = requirements.RequirementFile(name, contents)

        for remediation in req_remediations:
            pkg = remediation["requirement"]["name"]
            pkg_canonical_name: str = canonicalize_name(pkg)
            analyzed_spec: str = remediation["requirement"]["specifier"]

            # Skip remediations without a recommended version
            if remediation["recommended_version"] is None:
                LOG.debug(
                    f"The GitHub PR alerter only currently supports remediations that have a recommended_version: {pkg}"
                )
                continue

            # We have a single remediation that can have multiple vulnerabilities
            # Find all vulnerabilities associated with the remediation
            vulns = [
                x
                for x in obj.report["vulnerabilities"]
                if x["package_name"] == pkg_canonical_name
                and x["analyzed_requirement"]["specifier"] == analyzed_spec
            ]

            # Skip if all vulnerabilities have unknown severity and the ignore flag is set
            if ignore_cvss_unknown_severity and all(
                x["severity"] is None for x in vulns
            ):
                LOG.debug(
                    "All vulnerabilities have unknown severity, and ignore_cvss_unknown_severity is set."
                )
                continue

            highest_base_score = 0
            for vuln in vulns:
                if vuln["severity"] is not None:
                    highest_base_score = max(
                        highest_base_score,
                        (vuln["severity"].get("cvssv3", {}) or {}).get(
                            "base_score", 10
                        ),
                    )

            # Skip if none of the vulnerabilities meet the severity threshold
            if ignore_cvss_severity_below:
                at_least_one_match = False
                for vuln in vulns:
                    # Consider a None severity as a match, since it's controlled by a different flag
                    # If we can't find a base_score but we have severity data, assume it's critical for now.
                    if (
                        vuln["severity"] is None
                        or (vuln["severity"].get("cvssv3", {}) or {}).get(
                            "base_score", 10
                        )
                        >= ignore_cvss_severity_below
                    ):
                        at_least_one_match = True

                if not at_least_one_match:
                    LOG.debug(
                        f"None of the vulnerabilities found have a score greater than or equal to the ignore_cvss_severity_below of {ignore_cvss_severity_below}"
                    )
                    continue

            for parsed_req in parsed_req_file.requirements:
                specs = (
                    SpecifierSet(">=0")
                    if parsed_req.specs == SpecifierSet("")
                    else parsed_req.specs
                )

                # Check if the requirement matches the remediation
                if (
                    canonicalize_name(parsed_req.name) == pkg_canonical_name
                    and str(specs) == analyzed_spec
                ):
                    updated_contents = parsed_req.update_version(
                        contents, remediation["recommended_version"]
                    )
                    pending_updates.discard(f"{pkg_canonical_name}{analyzed_spec}")

                    new_branch = branch_prefix + utils.generate_branch_name(
                        pkg, remediation
                    )
                    skip_create = False

                    # Few possible cases:
                    # 1. No existing PRs exist for this change (don't need to handle)
                    # 2. An existing PR exists, and it's out of date (eg, recommended 0.5.1 and we want 0.5.2)
                    # 3. An existing PR exists, and it's not mergable anymore (eg, needs a rebase)
                    # 4. An existing PR exists, and everything's up to date.
                    # 5. An existing PR exists, but it's not needed anymore (perhaps we've been updated to a later version)
                    # 6. No existing PRs exist, but a branch does exist (perhaps the PR was closed but a stale branch left behind)
                    # In any case, we only act if we've been the only committer to the branch.
                    # Handle various cases for existing pull requests
                    for pr in pulls:
                        if not pr.head.ref.startswith(branch_prefix):
                            continue

                        authors = [
                            commit.committer.login for commit in pr.get_commits()
                        ]
                        only_us = all([x == self_user for x in authors])

                        try:
                            _, pr_pkg, pr_spec, pr_ver = pr.head.ref.split("/")
                        except ValueError:
                            # It's possible that something weird has manually been done, so skip that
                            # Skip invalid branch names
                            LOG.debug(
                                "Found an invalid branch name on an open PR, that matches our prefix. Skipping."
                            )
                            continue

                        pr_pkg = canonicalize_name(pr_pkg)

                        if pr_pkg != pkg_canonical_name:
                            continue

                        # Case 4: An up-to-date PR exists
                        if (
                            pr_pkg == pkg_canonical_name
                            and pr_spec == analyzed_spec
                            and pr_ver == remediation["recommended_version"]
                            and pr.mergeable
                        ):
                            LOG.debug(
                                f"An up to date PR #{pr.number} for {pkg} was found, no action will be taken."
                            )

                            skip_create = True
                            continue

                        if not only_us:
                            LOG.debug(
                                f"There are other committers on the PR #{pr.number} for {pkg}. No further action will be taken."
                            )
                            continue

                        # Case 2: An existing PR is out of date
                        if (
                            pr_pkg == pkg_canonical_name
                            and pr_spec == analyzed_spec
                            and pr_ver != remediation["recommended_version"]
                        ):
                            LOG.debug(
                                f"Closing stale PR #{pr.number} for {pkg} as a newer recommended version became"
                            )

                            pr.create_issue_comment(
                                "This PR has been replaced, since a newer recommended version became available."
                            )
                            pr.edit(state="closed")
                            delete_branch(repo, pr.head.ref)

                        # Case 3: An existing PR is not mergeable
                        if not pr.mergeable:
                            LOG.debug(
                                f"Closing PR #{pr.number} for {pkg} as it has become unmergable and we were the only committer"
                            )

                            pr.create_issue_comment(
                                "This PR has been replaced since it became unmergable."
                            )
                            pr.edit(state="closed")
                            delete_branch(repo, pr.head.ref)

                    # Skip if no changes were made
                    if updated_contents == contents:
                        LOG.debug(
                            f"Couldn't update {pkg} to {remediation['recommended_version']}"
                        )
                        continue

                    # Skip creation if indicated
                    if skip_create:
                        continue

                    # Create a new branch and commit the changes
                    try:
                        create_branch(repo, repo.default_branch, new_branch)
                    except pygithub.GithubException as e:
                        if e.data["message"] == "Reference already exists":
                            # There might be a stale branch. If the bot is the only committer, nuke it.
                            comparison = repo.compare(repo.default_branch, new_branch)
                            authors = [
                                commit.committer.login for commit in comparison.commits
                            ]
                            only_us = all([x == self_user for x in authors])

                            if only_us:
                                delete_branch(repo, new_branch)
                                create_branch(repo, repo.default_branch, new_branch)
                            else:
                                LOG.debug(
                                    f"The branch '{new_branch}' already exists - but there is no matching PR and this branch has committers other than us. This remediation will be skipped."
                                )
                                continue
                        else:
                            raise e

                    try:
                        repo.update_file(
                            path=name,
                            message=utils.generate_commit_message(pkg, remediation),
                            content=updated_contents,
                            branch=new_branch,
                            sha=utils.git_sha1(raw_contents),
                        )
                    except pygithub.GithubException as e:
                        if "does not match" in e.data["message"]:
                            click.secho(
                                f"GitHub blocked a commit on our branch to the requirements file, {name}, as the local hash we computed didn't match the version on {repo.default_branch}. Make sure you're running safety against the latest code on your default branch.",
                                fg="red",
                            )
                            continue
                        else:
                            raise e

                    pr = repo.create_pull(
                        title=pr_prefix + utils.generate_title(pkg, remediation, vulns),
                        body=utils.generate_body(
                            pkg, remediation, vulns, api_key=obj.key
                        ),
                        head=new_branch,
                        base=repo.default_branch,
                    )
                    LOG.debug(f"Created Pull Request to update {pkg}")

                    created += 1

                    # Add assignees and labels to the PR
                    for assignee in assignees:
                        pr.add_to_assignees(assignee)

                    for label in labels:
                        pr.add_to_labels(label)

                    if label_severity:
                        score_as_label = utils.cvss3_score_to_label(highest_base_score)
                        if score_as_label:
                            pr.add_to_labels(score_as_label)

    if len(pending_updates) > 0:
        click.secho(
            "The following remediations were not followed: {}".format(
                ", ".join(pending_updates)
            ),
            fg="red",
        )

    if created:
        click.secho(
            f"Safety successfully created {created} GitHub PR{'s' if created > 1 else ''} for repo {repo_name}"
        )
    else:
        click.secho(
            "No PRs created; please run the command with debug mode for more information."
        )


@click.command()
@click.option("--repo", help="GitHub standard repo path (eg, my-org/my-project)")
@click.option("--token", help="GitHub Access Token")
@click.option(
    "--base-url",
    help="Optional custom Base URL, if you're using GitHub enterprise",
    default=None,
)
@click.pass_obj
@utils.require_files_report  # TODO: For now, it can be removed in the future to support env scans.
def github_issue(obj: Any, repo: str, token: str, base_url: Optional[str]) -> None:
    """
    Create a GitHub Issue for any vulnerabilities found using PyUp's remediation data.

    Normally, this is run by a GitHub action. If you're running this manually, ensure that your local repo is up to date and on HEAD - otherwise you'll see strange results.

    Args:
        obj (Any): The Click context object containing report data.
        repo (str): The GitHub repository path.
        token (str): The GitHub Access Token.
        base_url (Optional[str]): Custom base URL for GitHub Enterprise, if applicable.
    """
    LOG.info("github_issue")

    if pygithub is None:
        click.secho(
            "pygithub is not installed. Did you install Safety with GitHub support? Try pip install safety[github]",
            fg="red",
        )
        sys.exit(1)

    # Load alert configurations from the policy
    alert = obj.policy.get("alert", {}) or {}
    security = alert.get("security", {}) or {}
    config_issue = security.get("github-issue", {}) or {}

    issue_prefix = config_issue.get("issue-prefix", "[PyUp] ")
    assignees = config_issue.get("assignees", [])
    labels = config_issue.get("labels", ["security"])

    label_severity = config_issue.get("label-severity", True)
    ignore_cvss_severity_below = config_issue.get("ignore-cvss-severity-below", 0)
    ignore_cvss_unknown_severity = config_issue.get(
        "ignore-cvss-unknown-severity", False
    )

    # Authenticate with GitHub
    gh = pygithub.Github(token, **({"base_url": base_url} if base_url else {}))
    repo_name = repo
    repo = gh.get_repo(repo)

    # Get all open issues for the repository
    issues = list(repo.get_issues(state="open", sort="created"))
    ISSUE_TITLE_REGEX = re.escape(issue_prefix) + r"Security Vulnerability in (.+)"
    req_remediations = list(
        itertools.chain.from_iterable(
            rem.get("requirements", {}).values()
            for pkg_name, rem in obj.report["remediations"].items()
        )
    )

    created = 0

    # Iterate over all requirements files and process each remediation
    for name, contents in obj.requirements_files.items():
        contents = contents.decode("utf-8")  # TODO - encoding?
        parsed_req_file = requirements.RequirementFile(name, contents)

        for remediation in req_remediations:
            pkg: str = remediation["requirement"]["name"]
            pkg_canonical_name: str = canonicalize_name(pkg)
            analyzed_spec: str = remediation["requirement"]["specifier"]

            # Skip remediations without a recommended version
            if remediation["recommended_version"] is None:
                LOG.debug(
                    f"The GitHub Issue alerter only currently supports remediations that have a recommended_version: {pkg}"
                )
                continue

            # We have a single remediation that can have multiple vulnerabilities
            # Find all vulnerabilities associated with the remediation
            vulns = [
                x
                for x in obj.report["vulnerabilities"]
                if x["package_name"] == pkg_canonical_name
                and x["analyzed_requirement"]["specifier"] == analyzed_spec
            ]

            # Skip if all vulnerabilities have unknown severity and the ignore flag is set
            if ignore_cvss_unknown_severity and all(
                x["severity"] is None for x in vulns
            ):
                LOG.debug(
                    "All vulnerabilities have unknown severity, and ignore_cvss_unknown_severity is set."
                )
                continue

            highest_base_score = 0
            for vuln in vulns:
                if vuln["severity"] is not None:
                    highest_base_score = max(
                        highest_base_score,
                        (vuln["severity"].get("cvssv3", {}) or {}).get(
                            "base_score", 10
                        ),
                    )

            # Skip if none of the vulnerabilities meet the severity threshold
            if ignore_cvss_severity_below:
                at_least_one_match = False
                for vuln in vulns:
                    # Consider a None severity as a match, since it's controlled by a different flag
                    # If we can't find a base_score but we have severity data, assume it's critical for now.
                    if (
                        vuln["severity"] is None
                        or (vuln["severity"].get("cvssv3", {}) or {}).get(
                            "base_score", 10
                        )
                        >= ignore_cvss_severity_below
                    ):
                        at_least_one_match = True
                        break

                if not at_least_one_match:
                    LOG.debug(
                        f"None of the vulnerabilities found have a score greater than or equal to the ignore_cvss_severity_below of {ignore_cvss_severity_below}"
                    )
                    continue

            for parsed_req in parsed_req_file.requirements:
                specs = (
                    SpecifierSet(">=0")
                    if parsed_req.specs == SpecifierSet("")
                    else parsed_req.specs
                )
                if (
                    canonicalize_name(parsed_req.name) == pkg_canonical_name
                    and str(specs) == analyzed_spec
                ):
                    skip = False
                    for issue in issues:
                        match = re.match(ISSUE_TITLE_REGEX, issue.title)
                        if match:
                            group = match.group(1)
                            if (
                                group == f"{pkg}{analyzed_spec}"
                                or group == f"{pkg_canonical_name}{analyzed_spec}"
                            ):
                                skip = True
                                break

                    # For now, we just skip issues if they already exist - we don't try and update them.
                    # Skip if an issue already exists for this remediation
                    if skip:
                        LOG.debug(
                            f"An issue already exists for {pkg}{analyzed_spec} - skipping"
                        )
                        continue

                    # Create a new GitHub issue
                    pr = repo.create_issue(
                        title=issue_prefix
                        + utils.generate_issue_title(pkg, remediation),
                        body=utils.generate_issue_body(
                            pkg, remediation, vulns, api_key=obj.key
                        ),
                    )
                    created += 1
                    LOG.debug(f"Created issue to update {pkg}")

                    # Add assignees and labels to the issue
                    for assignee in assignees:
                        pr.add_to_assignees(assignee)

                    for label in labels:
                        pr.add_to_labels(label)

                    if label_severity:
                        score_as_label = utils.cvss3_score_to_label(highest_base_score)
                        if score_as_label:
                            pr.add_to_labels(score_as_label)

    if created:
        click.secho(
            f"Safety successfully created {created} new GitHub Issue{'s' if created > 1 else ''} for repo {repo_name}"
        )
    else:
        click.secho(
            "No issues created; please run the command with debug mode for more information."
        )
