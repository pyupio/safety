"""Levenshtein edit distance, implemented from the standard Wagner-Fischer
dynamic-programming recurrence.
"""

# Both functions build a DP row per character of the longer string, so cost
# grows with len(s1) * len(s2) over untrusted input. Reject oversized strings
# instead of letting a single distance query become a CPU/memory DoS.
MAX_INPUT_LEN = 2000


def _check_input_len(s1: str, s2: str) -> None:
    longest = max(len(s1), len(s2))
    if longest > MAX_INPUT_LEN:
        raise ValueError(
            f"edit distance input length {longest} exceeds MAX_INPUT_LEN "
            f"({MAX_INPUT_LEN}); comparing long untrusted strings is a "
            "CPU/memory DoS risk"
        )


def edit_distance(s1: str, s2: str) -> int:
    """Number of single-character inserts, deletes, or substitutions needed
    to turn `s1` into `s2`."""
    _check_input_len(s1, s2)
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    if not s2:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, char1 in enumerate(s1, 1):
        current_row = [i]
        for j, char2 in enumerate(s2, 1):
            current_row.append(
                min(
                    previous_row[j] + 1,
                    current_row[j - 1] + 1,
                    previous_row[j - 1] + (char1 != char2),
                )
            )
        previous_row = current_row
    return previous_row[-1]


def is_within_distance(s1: str, s2: str, max_distance: int) -> bool:
    """True iff `edit_distance(s1, s2) <= max_distance`.

    Returns as soon as the answer is knowable: a length gap wider than
    `max_distance` fails without any DP work, and the row scan stops once
    every cell in a row exceeds `max_distance` (no later cell can shrink).
    """
    # These two shortcuts are O(n) and answer without any DP work, so they
    # deliberately run before the oversized-input guard; only the DP scan
    # below is DoS-prone.
    if abs(len(s1) - len(s2)) > max_distance:
        return False
    if s1 == s2:
        return True
    _check_input_len(s1, s2)
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    previous_row = list(range(len(s2) + 1))
    for i, char1 in enumerate(s1, 1):
        current_row = [i]
        row_min = i
        for j, char2 in enumerate(s2, 1):
            cost = min(
                previous_row[j] + 1,
                current_row[j - 1] + 1,
                previous_row[j - 1] + (char1 != char2),
            )
            current_row.append(cost)
            row_min = min(row_min, cost)
        if row_min > max_distance:
            return False
        previous_row = current_row
    return previous_row[-1] <= max_distance
