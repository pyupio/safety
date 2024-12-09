import os
import unittest

from unittest.mock import patch, Mock
from click.testing import CliRunner
from safety.cli import cli

from safety.scan.command import scan
from safety.scan.command import scan_project_app

class TestScanCommand(unittest.TestCase):

    def setUp(self):
        self.runner = CliRunner(mix_stderr=False)
        self.dirname = os.path.dirname(__file__)

    def test_scan(self):
        result = self.runner.invoke(cli, ["--stage", "cicd", "scan", "--target", self.dirname, "--output", "json"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(cli, ["--stage", "production", "scan", "--target", self.dirname, "--output", "json"])
        self.assertEqual(result.exit_code, 1)

        result = self.runner.invoke(cli, ["--stage", "cicd", "scan", "--target", self.dirname, "--output", "screen"])
        self.assertEqual(result.exit_code, 1)
