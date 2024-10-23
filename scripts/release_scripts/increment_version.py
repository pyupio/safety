import subprocess
import re
from datetime import date
import sys
import tempfile
import shutil
import os


def get_current_version(file_path: str) -> str:
    """
    Read the current version from the specified version file.

    Args:
        file_path (str): Path to the version file.

    Returns:
        str: The current version as a string.

    Raises:
        FileNotFoundError: If the version file does not exist.
        IOError: If an error occurs while reading the version file.
    """
    try:
        with open(file_path, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(f"Version file not found: {file_path}")
    except IOError as e:
        raise IOError(f"Error reading version file: {e}")


def get_last_version_from_changelog(file_path: str) -> str:
    """
    Extract the last version noted in the changelog file.

    Args:
        file_path (str): Path to the changelog file.

    Returns:
        str: The last version noted in the changelog.

    Raises:
        FileNotFoundError: If the changelog file does not exist.
        IOError: If an error occurs while reading the changelog file.
        ValueError: If no valid version entry is found in the changelog.
    """
    try:
        with open(file_path, "r") as file:
            content = file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Changelog file not found: {file_path}")
    except IOError as e:
        raise IOError(f"Error reading changelog file: {e}")

    match = re.search(r"\[(\d+\.\d+\.\d+)\] - (?:\d{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])", content)
    if not match:
        raise ValueError("No valid version entry found in changelog")
    return match.group(1)


def increment_version(version: str, bump_type: str) -> str:
    """
    Increment the version number based on the bump type.

    Args:
        version (str): The current version in the format 'major.minor.patch'.
        bump_type (str): The type of version bump, either 'major', 'minor', or 'patch'.

    Returns:
        str: The incremented version.

    Raises:
        ValueError: If the bump type is not 'major', 'minor', or 'patch'.
    """
    major, minor, patch = map(int, version.split("."))

    if bump_type == "major":
        major += 1
        minor = 0
        patch = 0
    elif bump_type == "minor":
        minor += 1
        patch = 0
    elif bump_type == "patch":
        patch += 1
    else:
        raise ValueError("Invalid bump type. Use 'major', 'minor', or 'patch'.")

    return f"{major}.{minor}.{patch}"


def update_version_file(file_path: str, new_version: str):
    """
    Update the specified version file with the new version.

    Args:
        file_path (str): Path to the version file.
        new_version (str): The new version to write into the file.
    """
    with open(file_path, "w") as file:
        file.write(new_version)


def get_git_commits_since_last_version(last_version: str) -> str:
    """
    Get all git commits since the specified last version.

    Args:
        last_version (str): The last version noted in the changelog.

    Returns:
        str: A string containing commit messages since the last version.

    Raises:
        RuntimeError: If the git command fails.
    """
    result = subprocess.run(
        ["git", "log", f"{last_version}..HEAD", "--pretty=format:%s (%h)"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Error running git log: {result.stderr}")
    return result.stdout.strip()


def format_commit_message(commit_message: str) -> str:
    """
    Format the commit message according to the changelog format.

    Args:
        commit_message (str): The commit message to format.

    Returns:
        str: The formatted commit message or None if it is a merge commit.
    """
    if "Merge pull request" in commit_message:
        return None

    slash_index = commit_message.find("/")
    if slash_index != -1:
        commit_message = (
            commit_message[:slash_index] + ": " + commit_message[slash_index + 1:]
        )
        return f"- {commit_message}"
    else:
        commit_types = ['feat', 'fix', 'docs', 'style', 'refactor', 'test', 'chore']
        for type_ in commit_types:
            if commit_message.startswith(f"{type_}:"):
                return f"- {commit_message}"
        return f"- other: {commit_message}"


def update_changelog(file_path: str, new_version: str, new_commits: str):
    """
    Add a new version and its corresponding commits to the changelog.

    Args:
        file_path (str): Path to the changelog file.
        new_version (str): The new version number.
        new_commits (str): A string containing commit messages for the new version.

    Raises:
        ValueError: If the changelog header is missing.
        Exception: If an error occurs while updating the changelog file.
    """
    today = date.today().strftime("%Y-%m-%d")
    formatted_commits = "\n".join(
        formatted_commit
        for commit in new_commits.split("\n")
        if (formatted_commit := format_commit_message(commit))
    )

    new_changelog_entry = f"## [{new_version}] - {today}\n{formatted_commits}\n"
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)

    try:
        with open(file_path, "r") as file:
            content = file.read()

            if "[PEP 440](https://peps.python.org/pep-0440/)" in content:
                content = content.replace(
                    "[PEP 440](https://peps.python.org/pep-0440/)",
                    "[PEP 440](https://peps.python.org/pep-0440/)\n",
                )

            changelog_header_index = content.find("# Changelog")
            if changelog_header_index == -1:
                raise ValueError("Changelog file is missing the '# Changelog' header")

            insertion_point = content.find("\n## [", changelog_header_index)
            if insertion_point == -1:
                insertion_point = len(content)

            updated_content = (
                content[:insertion_point] + new_changelog_entry + content[insertion_point:]
            )

            temp_file.write(updated_content)
            temp_file.close()
            shutil.move(temp_file.name, file_path)
    except Exception as e:
        os.unlink(temp_file.name)
        raise e


def main():
    """
    Main entry point for the script.

    Validates the arguments, increments the version, and updates the changelog.
    """
    if len(sys.argv) < 2:
        print("Usage: python script.py <bump_type>")
        print("bump_type: major, minor, or patch")
        return

    bump_type = sys.argv[1]
    version_file = "safety/VERSION"
    changelog_file = "CHANGELOG.md"

    current_version = get_current_version(version_file)
    last_version = get_last_version_from_changelog(changelog_file)

    if not last_version:
        print("No previous version found in changelog.")
        return

    new_version = increment_version(current_version, bump_type)
    update_version_file(version_file, new_version)

    commits = get_git_commits_since_last_version(last_version)
    if not commits:
        print("No new commits since the last version.")
        return

    update_changelog(changelog_file, new_version, commits)
    print(f"CHANGELOG.MD updated with version {new_version}")


if __name__ == "__main__":
    main()
