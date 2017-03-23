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
from safety import util
import os
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


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


class TestSafety(unittest.TestCase):

    def test_check(self):
        reqs = StringIO("Django==1.8.1")
        packages = util.read_requirements(reqs)

        vulns = safety.check(
            packages=packages,
            db_mirror=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "test_db"
            ),
            cached=False,
            key=False
        )
        self.assertEqual(len(vulns), 2)
