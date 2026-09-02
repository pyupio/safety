# Natural Language Toolkit: Distance Metrics
#
# Copyright (C) 2001-2026 NLTK Project
# Author: Edward Loper <edloper@gmail.com>
#         Steven Bird <stevenbird1@gmail.com>
#         Tom Lippincott <tom@cs.columbia.edu>
# URL: <https://www.nltk.org/>
# For license information, see LICENSES/Apache-2.0.txt.
#
# Modified by Safety CLI on 2026-09-02:
# - Extracted the edit-distance implementation from NLTK v3.10.3.
# - Removed unrelated metrics and imports.
# - Repointed the license reference, and rewrote the
#   MAX_DISTANCE_INPUT_LEN comment, the _check_distance_input_len
#   docstring and its error message, so they describe only the
#   edit_distance vendored here rather than metrics left behind.
# Source: https://github.com/nltk/nltk/blob/v3.10.3/nltk/metrics/distance.py

#: Maximum input length accepted by :func:`edit_distance`, which is O(n*m) in
#: both time and memory (it builds a full ``(n+1)x(m+1)`` DP matrix) over two
#: untrusted strings. An unbounded length is therefore a CPU/memory DoS
#: (CWE-407, CWE-400): ``edit_distance("a"*40000, "b"*40000)`` allocates tens
#: of GB and runs for hours. A real distance query is short; raise this if you
#: genuinely need to compare very long, trusted strings.
MAX_DISTANCE_INPUT_LEN = 2000


def _check_distance_input_len(s1, s2, func_name):
    """Reject oversized inputs to the O(n*m) distance function."""
    longest = max(len(s1), len(s2))
    if longest > MAX_DISTANCE_INPUT_LEN:
        raise ValueError(
            f"{func_name}: input length {longest} exceeds MAX_DISTANCE_INPUT_LEN "
            f"({MAX_DISTANCE_INPUT_LEN}). This function is super-linear in the "
            "input length over two untrusted strings (CWE-407/CWE-400); a long "
            "input is a CPU/memory DoS. Raise safety.tool._vendor.nltk_distance."
            "MAX_DISTANCE_INPUT_LEN if you need to compare longer trusted strings."
        )


def _edit_dist_init(len1, len2):
    lev = []
    for i in range(len1):
        lev.append([0] * len2)  # initialize 2D array to zero
    for i in range(len1):
        lev[i][0] = i  # column 0: 0,1,2,3,4,...
    for j in range(len2):
        lev[0][j] = j  # row 0: 0,1,2,3,4,...
    return lev


def _last_left_t_init(sigma):
    return {c: 0 for c in sigma}


def _edit_dist_step(
    lev, i, j, s1, s2, last_left, last_right, substitution_cost=1, transpositions=False
):
    c1 = s1[i - 1]
    c2 = s2[j - 1]

    # skipping a character in s1
    a = lev[i - 1][j] + 1
    # skipping a character in s2
    b = lev[i][j - 1] + 1
    # substitution
    c = lev[i - 1][j - 1] + (substitution_cost if c1 != c2 else 0)

    # transposition
    d = c + 1  # never picked by default
    if transpositions and last_left > 0 and last_right > 0:
        d = lev[last_left - 1][last_right - 1] + i - last_left + j - last_right - 1

    # pick the cheapest
    lev[i][j] = min(a, b, c, d)


def edit_distance(s1, s2, substitution_cost=1, transpositions=False):
    """
    Calculate the Levenshtein edit-distance between two strings.
    The edit distance is the number of characters that need to be
    substituted, inserted, or deleted, to transform s1 into s2.  For
    example, transforming "rain" to "shine" requires three steps,
    consisting of two substitutions and one insertion:
    "rain" -> "sain" -> "shin" -> "shine".  These operations could have
    been done in other orders, but at least three steps are needed.

    Allows specifying the cost of substitution edits (e.g., "a" -> "b"),
    because sometimes it makes sense to assign greater penalties to
    substitutions.

    This also optionally allows transposition edits (e.g., "ab" -> "ba"),
    though this is disabled by default.

    :param s1, s2: The strings to be analysed
    :param transpositions: Whether to allow transposition edits
    :type s1: str
    :type s2: str
    :type substitution_cost: int
    :type transpositions: bool
    :rtype: int
    """
    _check_distance_input_len(s1, s2, "edit_distance")
    # set up a 2-D array
    len1 = len(s1)
    len2 = len(s2)
    lev = _edit_dist_init(len1 + 1, len2 + 1)

    # retrieve alphabet
    sigma = set()
    sigma.update(s1)
    sigma.update(s2)

    # set up table to remember positions of last seen occurrence in s1
    last_left_t = _last_left_t_init(sigma)

    # iterate over the array
    # i and j start from 1 and not 0 to stay close to the wikipedia pseudo-code
    # see https://en.wikipedia.org/wiki/Damerau%E2%80%93Levenshtein_distance
    for i in range(1, len1 + 1):
        last_right_buf = 0
        for j in range(1, len2 + 1):
            last_left = last_left_t[s2[j - 1]]
            last_right = last_right_buf
            if s1[i - 1] == s2[j - 1]:
                last_right_buf = j
            _edit_dist_step(
                lev,
                i,
                j,
                s1,
                s2,
                last_left,
                last_right,
                substitution_cost=substitution_cost,
                transpositions=transpositions,
            )
        last_left_t[s1[i - 1]] = i
    return lev[len1][len2]
