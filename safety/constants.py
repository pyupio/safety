# -*- coding: utf-8 -*-
import os

JSON_SCHEMA_VERSION = '2.0.0'

OPEN_MIRRORS = [
    f"https://pyup.io/aws/safety/free/{JSON_SCHEMA_VERSION}/",
]

API_VERSION = 'v1/'
SAFETY_ENDPOINT = 'safety/'
API_BASE_URL = 'https://pyup.io/api/' + API_VERSION + SAFETY_ENDPOINT

API_MIRRORS = [
    API_BASE_URL
]

REQUEST_TIMEOUT = 5

CACHE_FILE = os.path.join(
    os.path.expanduser("~"),
    ".safety",
    f"{JSON_SCHEMA_VERSION.replace('.', '')}",
    "cache.json"
)

# Colors
YELLOW = 'yellow'
RED = 'red'
GREEN = 'green'

# MESSAGES
IGNORE_UNPINNED_REQ_REASON = \
    "This vulnerability is being ignored due to the 'ignore-unpinned-requirements' flag (default True). " \
    "To change this, set 'ignore-unpinned-requirements' to False under 'security' in your policy file. " \
    "See https://docs.pyup.io/docs/safety-20-policy-file for more information."

# REGEXES
HASH_REGEX_GROUPS = r"--hash[=| ](\w+):(\w+)"

# Exit codes
EXIT_CODE_OK = 0
EXIT_CODE_FAILURE = 1
EXIT_CODE_VULNERABILITIES_FOUND = 64
EXIT_CODE_INVALID_API_KEY = 65
EXIT_CODE_TOO_MANY_REQUESTS = 66
EXIT_CODE_UNABLE_TO_LOAD_LOCAL_VULNERABILITY_DB = 67
EXIT_CODE_UNABLE_TO_FETCH_VULNERABILITY_DB = 68
EXIT_CODE_MALFORMED_DB = 69
EXIT_CODE_INVALID_PROVIDED_REPORT = 70
EXIT_CODE_INVALID_REQUIREMENT = 71
