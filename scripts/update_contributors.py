import sys
import os
from typing import List, Optional

# Constants
TIERS = {
    "Valued Contributor": 10,
    "Frequent Contributor": 5,
    "First Contributor": 1
}
CONTRIBUTORS_FILE_NAME = "CONTRIBUTORS.md"
BADGE_COLOR = "blue"

def get_contributors_file_path() -> str:
    """
    Construct the file path for CONTRIBUTORS.md based on the script's location.

    Returns:
        str: The path to the CONTRIBUTORS.md file.
    """
    return os.path.join(os.path.dirname(__file__), '..', CONTRIBUTORS_FILE_NAME)

def update_contributor_line(contributor: str, pr_count: int) -> Optional[str]:
    """
    Generate the appropriate line for the contributor based on their PR count.

    Args:
        contributor (str): The GitHub username of the contributor.
        pr_count (int): The number of merged PRs for the contributor.

    Returns:
        Optional[str]: The formatted line for the contributor or None if no matching tier is found.
    """
    for tier, count in TIERS.items():
        if pr_count >= count:
            return f"| @{contributor} | ![{tier} Badge](https://img.shields.io/badge/{tier.replace(' ', '%20')}-Achieved-{BADGE_COLOR}) |\n"
    return None

def main() -> None:
    """
    Main function to update the CONTRIBUTORS.md file.

    The function reads the CONTRIBUTORS.md file, updates or adds the contributor's
    information based on their PR count, and writes the changes back to the file.
    """
    # Parse command-line arguments
    contributor = sys.argv[1]
    pr_count = int(sys.argv[2])

    # Get the path to the CONTRIBUTORS.md file
    contributors_file_path = get_contributors_file_path()

    # Read the existing lines in the CONTRIBUTORS.md file
    with open(contributors_file_path, "r") as file:
        lines = file.readlines()

    found = False  # Flag to check if the contributor is already in the file
    new_lines: List[str] = []

    # Update the contributor's line if they are already in the file
    for line in lines:
        if contributor in line:
            found = True
            updated_line = update_contributor_line(contributor, pr_count)
            if updated_line:
                line = updated_line
        new_lines.append(line)

    # If the contributor is not found, add a new line for them
    if not found:
        new_contributor_line = update_contributor_line(contributor, pr_count)
        if new_contributor_line:
            new_lines.append(new_contributor_line)

    # Write the updated lines back to the CONTRIBUTORS.md file
    with open(contributors_file_path, "w") as file:
        file.writelines(new_lines)

if __name__ == "__main__":
    main()
