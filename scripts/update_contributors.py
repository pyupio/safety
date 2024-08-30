import sys
import os

contributor = sys.argv[1]
pr_count = int(sys.argv[2])

tiers = {
    "Valued Contributor": 10,
    "Frequent Contributor": 5,
    "First Contributor": 1
}

contributors_file_path = os.path.join(os.path.dirname(__file__), '..', 'CONTRIBUTORS.md')

with open(contributors_file_path, "r") as file:
    lines = file.readlines()

found = False
new_lines = []
for line in lines:
    if contributor in line:
        found = True
        for tier, count in tiers.items():
            if pr_count >= count:
                line = f"| @{contributor} | ![{tier} Badge](https://img.shields.io/badge/{tier.replace(' ', '%20')}-Achieved-blue) |\n"
                break
    new_lines.append(line)

if not found:
    for tier, count in tiers.items():
        if pr_count >= count:
            new_lines.append(f"| @{contributor} | ![{tier} Badge](https://img.shields.io/badge/{tier.replace(' ', '%20')}-Achieved-blue) |\n")
            break

with open(contributors_file_path, "w") as file:
    file.writelines(new_lines)
