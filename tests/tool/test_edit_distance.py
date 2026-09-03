"""
Test suite for the clean-room edit-distance module.

The golden corpus was generated once with nltk 3.10.3 (the implementation the
vendored code came from), so matching it proves behavior parity with what
shipped before.
"""

import json
from pathlib import Path

import pytest

from safety.tool.edit_distance import (
    MAX_INPUT_LEN,
    edit_distance,
    is_within_distance,
)

GOLDEN_PATH = Path(__file__).parent / "data" / "edit_distance_golden.json"


@pytest.fixture(scope="module")
def distance_cases():
    with GOLDEN_PATH.open() as f:
        return json.load(f)["distance_cases"]


@pytest.mark.unit
class TestEditDistance:
    """Golden-corpus parity and metric properties"""

    def test_matches_golden_corpus(self, distance_cases):
        mismatches = [
            (s1, s2, expected, edit_distance(s1, s2))
            for s1, s2, expected in distance_cases
            if edit_distance(s1, s2) != expected
        ]
        assert mismatches == []

    def test_is_within_distance_agrees_with_edit_distance(self, distance_cases):
        for s1, s2, expected in distance_cases:
            for max_distance in (1, 2):
                assert is_within_distance(s1, s2, max_distance) is (
                    expected <= max_distance
                ), (s1, s2, expected, max_distance)

    def test_identity_is_zero(self):
        for s in ("", "a", "requests", "a-b_c.1"):
            assert edit_distance(s, s) == 0

    def test_symmetry(self, distance_cases):
        for s1, s2, expected in distance_cases[:300]:
            assert edit_distance(s2, s1) == expected

    def test_empty_string_distance_is_other_length(self):
        assert edit_distance("", "abc") == 3
        assert edit_distance("abc", "") == 3
        assert edit_distance("", "") == 0

    def test_bounds_hold_on_every_golden_case(self, distance_cases):
        for s1, s2, expected in distance_cases:
            assert abs(len(s1) - len(s2)) <= expected <= max(len(s1), len(s2))

    def test_transposition_costs_two_edits(self):
        assert edit_distance("ab", "ba") == 2
        assert not is_within_distance("ab", "ba", 1)

    def test_oversized_input_raises(self):
        oversized = "a" * (MAX_INPUT_LEN + 1)
        with pytest.raises(ValueError):
            edit_distance(oversized, "b")
        with pytest.raises(ValueError):
            is_within_distance(oversized, "b" * (MAX_INPUT_LEN + 1), 2)

    def test_wide_length_gap_short_circuits_before_the_size_guard(self):
        # The O(1) length-gap check answers False without DP work, so it is
        # allowed to run before the oversized-input guard.
        assert is_within_distance("a" * (MAX_INPUT_LEN + 1), "b", 2) is False
