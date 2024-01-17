import os
from packaging.version import Version

raw_version = os.environ.get('SAFETY_VERSION', None)
if not raw_version:
    raise ValueError("Missing SAFETY_VERSION environment variable")

v = Version(raw_version)
major, minor = v.major, v.minor

with open(os.getenv('GITHUB_ENV'), "a") as env:
    print(f"SAFETY_MAJOR_VERSION={major}", file=env)
    print(f"SAFETY_MINOR_VERSION={minor}", file=env)
