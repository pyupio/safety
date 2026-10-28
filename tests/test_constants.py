import os
import unittest
from pathlib import Path
from unittest.mock import patch

from safety.constants import DIR_NAME, get_user_dir


class TestGetUserDir(unittest.TestCase):
    """Test cases for resolving the user config directory."""

    @patch.dict(os.environ)
    def test_defaults_to_home_directory(self):
        """Without the env var, the config dir lives in the user's home."""
        os.environ.pop("SAFETY_USER_CONFIG_PATH", None)
        self.assertEqual(get_user_dir(), Path("~", DIR_NAME).expanduser())

    @patch.dict(os.environ, {"SAFETY_USER_CONFIG_PATH": "/tmp/safety-config"})
    def test_env_var_overrides_base_directory(self):
        """SAFETY_USER_CONFIG_PATH replaces the home directory as the base."""
        self.assertEqual(get_user_dir(), Path("/tmp/safety-config", DIR_NAME))

    @patch.dict(os.environ, {"SAFETY_USER_CONFIG_PATH": "~/custom"})
    def test_env_var_expands_user(self):
        """A leading ~ in SAFETY_USER_CONFIG_PATH is expanded."""
        self.assertEqual(get_user_dir(), Path("~", "custom", DIR_NAME).expanduser())

    @patch.dict(os.environ, {"SAFETY_USER_CONFIG_PATH": ""})
    def test_empty_env_var_is_ignored(self):
        """An empty SAFETY_USER_CONFIG_PATH falls back to the home directory."""
        self.assertEqual(get_user_dir(), Path("~", DIR_NAME).expanduser())


if __name__ == "__main__":
    unittest.main()
