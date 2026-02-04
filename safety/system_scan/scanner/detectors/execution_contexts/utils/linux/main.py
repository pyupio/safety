from __future__ import annotations

import os
import stat


def get_linux_machine_id() -> str | None:
    """
    Get Linux machine ID from /etc/machine-id or /var/lib/dbus/machine-id.

    Returns:
        The machine ID or None if not found
    """
    paths = (
        "/etc/machine-id",
        "/var/lib/dbus/machine-id",
    )

    # machine-id is 32 hex chars + newline = 33 bytes
    # set a max size to avoid reading big files
    max_size = 64

    for path in paths:
        try:
            st = os.stat(path)

            # Reject if too large or not a regular file
            if st.st_size > max_size or not stat.S_ISREG(st.st_mode):
                continue

            with open(path, "r", encoding="utf-8") as f:
                value = f.read(max_size).strip()

            if value:
                return value

        except (OSError, ValueError):
            continue

    return None
