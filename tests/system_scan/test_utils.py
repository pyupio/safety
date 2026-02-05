from __future__ import annotations

import pytest

from safety.system_scan.utils import is_interactive_terminal


@pytest.mark.unit
class TestUtils:
    """Test utility functions."""

    def test_is_interactive_terminal_exists(self):
        """Test that is_interactive_terminal function exists and is callable."""
        # Just test that the function exists and returns a boolean
        result = is_interactive_terminal()
        assert isinstance(result, bool)
