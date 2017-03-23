#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_safety
----------------------------------

Tests for `safety` module.
"""


import sys
import unittest
from contextlib import contextmanager
from click.testing import CliRunner

from safety import safety
from safety import cli
from safety import formatter


class TestSafetyCLI(unittest.TestCase):

    def test_command_line_interface(self):
        runner = CliRunner()
        result = runner.invoke(cli.cli)
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        help_result = runner.invoke(cli.cli, ['--help'])
        assert help_result.exit_code == 0
        assert '--help' in help_result.output


class TestFormatter(unittest.TestCase):

    def test_get_terminal_size(self):
        try:
            formatter.get_terminal_size()
        except TypeError as e:
            self.fail(e)
