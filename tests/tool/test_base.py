"""
Regression tests for safety.tool.base.

Pins the subprocess.run encoding kwargs that fix the Windows cp1252
UnicodeDecodeError when npm/pip/etc. emit UTF-8 output (e.g. smart quotes
in package descriptions).
"""

import json
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest
import typer

from safety.tool.npm.command import NpmCommand


class TestGetInstalledPackagesEncoding:
    """
    BaseCommand._get_installed_packages must decode subprocess stdout as
    UTF-8 with errors='replace' regardless of the host locale.
    """

    def setup_method(self):
        self.ctx = MagicMock(spec=typer.Context)
        self.ctx.obj = MagicMock()

    @pytest.mark.unit
    @patch("safety.tool.base.get_unwrapped_command", return_value="npm")
    @patch("safety.tool.base.subprocess.run")
    def test_handles_utf8_output_with_smart_quote(self, mock_run, _mock_unwrapped):
        """
        UTF-8 stdout containing a smart quote (U+201D) must parse cleanly.
        Reproduces the customer crash on Windows where the default cp1252
        decoder choked on byte 0x9d.
        """
        payload = {
            "dependencies": {
                "quick-lru": {
                    "version": "5.2.0",
                    "path": "/x",
                    "description": "Simple “LRU” cache",
                }
            }
        }
        mock_run.return_value = CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(payload)
        )

        cmd = NpmCommand(["install", "resend"])
        result = cmd._get_installed_packages(self.ctx)

        assert result == [{"name": "quick-lru", "version": "5.2.0", "location": "/x"}]

    @pytest.mark.unit
    @patch("safety.tool.base.get_unwrapped_command", return_value="npm")
    @patch("safety.tool.base.subprocess.run")
    def test_subprocess_run_is_called_with_utf8_replace_kwargs(
        self, mock_run, _mock_unwrapped
    ):
        """
        Pins the fix: subprocess.run must be invoked with
        encoding='utf-8' and errors='replace'. The functional test above
        cannot reproduce the cp1252 crash because the subprocess layer
        is mocked, so this assertion is what actually defends the fix
        in the diff.
        """
        mock_run.return_value = CompletedProcess(
            args=[], returncode=0, stdout='{"dependencies": {}}'
        )

        cmd = NpmCommand(["list"])
        cmd._get_installed_packages(self.ctx)

        kwargs = mock_run.call_args.kwargs
        assert kwargs.get("text") is True
        assert kwargs.get("encoding") == "utf-8"
        assert kwargs.get("errors") == "replace"
