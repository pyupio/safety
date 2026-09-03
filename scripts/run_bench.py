#!/usr/bin/env python3
"""Drive the inline check_package timing instrumentation and print per-segment
numbers, plus a digest of the results so two runs can be compared for parity.

Run from the repo root of the tree under test. The instrumentation commit
cherry-picks cleanly onto the pre-change tree, so the before side runs with
identical timers; commands are in the PR.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.getcwd())

from safety.tool import typosquatting

_module_path = os.path.realpath(typosquatting.__file__)
assert _module_path.startswith(os.path.realpath(os.getcwd())), (
    f"imported {_module_path}, not the tree under test; run with python -S and "
    "PYTHONPATH pointing at this tree plus the venv site-packages"
)

from safety.tool.constants import (  # noqa: E402  (needs the sys.path insert above)
    MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES,
)
from safety.tool.typosquatting import TyposquattingProtection  # noqa: E402

POPULAR = MOST_FREQUENTLY_DOWNLOADED_PYPI_PACKAGES
REPS = 10
SEGMENTS = [
    ("typo'd popular names", [n[1:] for n in POPULAR[:60:3]]),
    (
        "unknown names (full scan, worst case)",
        ["my-internal-lib", "acme-billing-client", "torch-audio-tools"] * 5,
    ),
    ("exact matches", list(POPULAR[:10])),
]

protection = TyposquattingProtection(POPULAR)
results = {}
print(f"Python {sys.version.split()[0]}, {REPS} reps per segment, ms per batch")
for label, queries in SEGMENTS:
    results[label] = [protection.check_package(q) for q in queries]
    typosquatting._check_package_timings.clear()
    for _ in range(REPS):
        for q in queries:
            protection.check_package(q)
    batch_ms = sum(typosquatting._check_package_timings) / REPS * 1000
    print(f"  {label} ({len(queries)} queries): {batch_ms:.1f} ms")

digest = hashlib.sha256(json.dumps(results, sort_keys=True).encode()).hexdigest()
print(f"results digest (must match between before and after runs): {digest[:16]}")
