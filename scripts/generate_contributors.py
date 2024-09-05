import os
import requests
from collections import defaultdict

# Repository details and GitHub token
GITHUB_REPO = "pyupio/safety"
GITHUB_TOKEN = os.getenv("YOUR_GITHUB_TOKEN")
CONTRIBUTORS_FILE = "CONTRIBUTORS.md"

# Tier thresholds
TIERS = {"Valued Contributor": 10, "Frequent Contributor": 5, "First Contributor": 1}


# API request to get merged PRs
def get_merged_prs():
    prs = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/pulls?state=closed&per_page=100&page={page}"
        headers = {"Authorization": f"token {GITHUB_TOKEN}"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        page_prs = response.json()

        # Break if there are no more PRs
        if not page_prs:
            break

        prs.extend(page_prs)
        page += 1

    return prs


# Count contributions for each user
def count_contributions(prs):
    contributions = defaultdict(int)
    for pr in prs:
        if pr.get("merged_at"):
            user = pr["user"]["login"]
            contributions[user] += 1
    return contributions


# Categorize contributors by tier
def categorize_contributors(contributions):
    tiers = {tier: [] for tier in TIERS}
    for user, count in contributions.items():
        for tier, threshold in TIERS.items():
            if count >= threshold:
                tiers[tier].append((user, count))
                break
    return tiers


# Generate Shieldify badge
def generate_badge(user, tier):
    badge_url = f"https://img.shields.io/badge/{user.replace('-', '--')}-{tier.replace(' ', '%20')}-brightgreen"
    return f"![{user} Badge]({badge_url})"


# Generate CONTRIBUTORS.md content
def generate_contributors_md(tiers):
    lines = ["# Contributors\n"]
    for tier, contributors in tiers.items():
        if contributors:
            lines.append(f"## {tier}\n")
            for user, count in sorted(contributors, key=lambda x: x[1], reverse=True):
                badge = generate_badge(user, tier)
                lines.append(f"- {badge} ({count} merged PRs)\n")
    return "\n".join(lines)


# Write the CONTRIBUTORS.md file
def write_contributors_file(content):
    with open(CONTRIBUTORS_FILE, "w") as file:
        file.write(content)


def main():
    prs = get_merged_prs()
    contributions = count_contributions(prs)
    tiers = categorize_contributors(contributions)
    content = generate_contributors_md(tiers)
    write_contributors_file(content)
    print(f"{CONTRIBUTORS_FILE} generated successfully.")


if __name__ == "__main__":
    main()
