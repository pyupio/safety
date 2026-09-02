# NLTK third-party notice

`safety/tool/_vendor/nltk_distance.py` contains the edit-distance portion of
NLTK's `nltk/metrics/distance.py` from v3.10.3.

- Copyright (C) 2001-2026 NLTK Project
- License: Apache License 2.0 (`Apache-2.0.txt`)
- Source: https://github.com/nltk/nltk/blob/v3.10.3/nltk/metrics/distance.py
- Commit: `303f6e2ba8e4548a5f54fd65d86bb5c9a949f1db`
- Upstream file SHA-256: `caa1d4f040d2468d4b6e9ba75a7c0e5bf88cd740656f96e7df5dc40184df288b`

Safety CLI extracted the edit-distance implementation and removed unrelated
metrics and imports. Comments, docstrings and error messages that named the
removed metrics or upstream module paths were rewritten to describe only what
is vendored here. The original copyright and author header is retained in the
vendored source file, and the file states the modifications inline.
