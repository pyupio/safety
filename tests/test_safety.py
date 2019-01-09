#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_safety
----------------------------------

Tests for `safety` module.
"""


import unittest
import textwrap
from click.testing import CliRunner

from safety import safety
from safety import cli
from safety import formatter
from safety import util
import os
import json
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO
from safety.util import read_requirements
from safety.util import read_vulnerabilities


class TestSafetyCLI(unittest.TestCase):

    def test_command_line_interface(self):
        runner = CliRunner()
        result = runner.invoke(cli.cli)
        assert result.exit_code == 0
        assert 'Usage:' in result.output
        help_result = runner.invoke(cli.cli, ['--help'])
        assert help_result.exit_code == 0
        assert '--help' in help_result.output

    def test_review_pass(self):
        runner = CliRunner()
        dirname = os.path.dirname(__file__)
        path_to_report = os.path.join(dirname, "test_db", "example_report.json")
        result = runner.invoke(cli.cli, ['review', '--bare', '--file', path_to_report])
        assert result.exit_code == 0
        assert result.output == u'django\n'

    def test_review_fail(self):
        runner = CliRunner()
        dirname = os.path.dirname(__file__)
        path_to_report = os.path.join(dirname, "test_db", "invalid_example_report.json")
        result = runner.invoke(cli.cli, ['review', '--bare', '--file', path_to_report])
        assert result.exit_code == -1


class TestFormatter(unittest.TestCase):

    maxDiff = None

    def test_get_terminal_size(self):
        try:
            formatter.get_terminal_size()
        except TypeError as e:
            self.fail(e)

    def test_report_json(self):
        test_arr = [['libfoo'], ['libbar']]
        json_report = formatter.report(test_arr, full=False, json_report=True)
        assert json.loads(json_report) == test_arr

    def test_get_used_db(self):
        assert 'default DB' == formatter.get_used_db(key=None, db='')
        assert 'pyup.io\'s DB' == formatter.get_used_db(key='foo', db='')
        assert 'local DB' == formatter.get_used_db(key=None, db='/usr/local/some-db')

    def test_full_report(self):
        vulns = [
            safety.Vulnerability(
                name='libfoo',
                spec='<2.0.0',
                version='1.9.3',
                advisory='libfoo prior to version 2.0.0 had a vulnerability'
                         + ' blah' * 15 + '.\r\n\r\n'
                         + 'All users are urged to upgrade please.\r\n',
                vuln_id=1234,
            ),
        ]
        full_report = formatter.SheetReport.render(
            vulns, full=True, checked_packages=5, used_db='test DB')
        self.assertMultiLineEqual(full_report + "\n", textwrap.dedent(r"""
            ╒══════════════════════════════════════════════════════════════════════════════╕
            │                                                                              │
            │                               /$$$$$$            /$$                         │
            │                              /$$__  $$          | $$                         │
            │           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           │
            │          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           │
            │         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           │
            │          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           │
            │          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           │
            │         |_______/  \_______/|__/     \_______/   \___/   \____  $$           │
            │                                                          /$$  | $$           │
            │                                                         |  $$$$$$/           │
            │  by pyup.io                                              \______/            │
            │                                                                              │
            ╞══════════════════════════════════════════════════════════════════════════════╡
            │ REPORT                                                                       │
            │ checked 5 packages, using test DB                                            │
            ╞════════════════════════════╤═══════════╤══════════════════════════╤══════════╡
            │ package                    │ installed │ affected                 │ ID       │
            ╞════════════════════════════╧═══════════╧══════════════════════════╧══════════╡
            │ libfoo                     │ 1.9.3     │ <2.0.0                   │     1234 │
            ╞══════════════════════════════════════════════════════════════════════════════╡
            │ libfoo prior to version 2.0.0 had a vulnerability blah blah blah blah blah   │
            │ blah blah blah blah blah blah blah blah blah blah.                           │
            │                                                                              │
            │ All users are urged to upgrade please.                                       │
            ╘══════════════════════════════════════════════════════════════════════════════╛
            """.lstrip('\n')))


class TestSafety(unittest.TestCase):
    def test_review_from_file(self):
        dirname = os.path.dirname(__file__)
        path_to_report = os.path.join(dirname, "test_db", "example_report.json")
        with open(path_to_report) as insecure:
            input_vulns = read_vulnerabilities(insecure)

        vulns = safety.review(input_vulns)
        assert(len(vulns), 3)

    def test_check_from_file(self):
        reqs = StringIO("Django==1.8.1")
        packages = util.read_requirements(reqs)

        vulns = safety.check(
            packages=packages,
            db_mirror=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "test_db"
            ),
            cached=False,
            key=False,
            ignore_ids=[],
            proxy={}
        )
        self.assertEqual(len(vulns), 2)

    def test_multiple_versions(self):
        reqs = StringIO("Django==1.8.1\n\rDjango==1.7.0")
        packages = util.read_requirements(reqs)

        vulns = safety.check(
            packages=packages,
            db_mirror=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "test_db"
            ),
            cached=False,
            key=False,
            ignore_ids=[],
            proxy={}
        )
        self.assertEqual(len(vulns), 4)

    def test_check_live(self):
        reqs = StringIO("insecure-package==0.1")
        packages = util.read_requirements(reqs)

        vulns = safety.check(
            packages=packages,
            db_mirror=False,
            cached=False,
            key=False,
            ignore_ids=[],
            proxy={}
        )
        self.assertEqual(len(vulns), 1)

    def test_check_live_cached(self):
        reqs = StringIO("insecure-package==0.1")
        packages = util.read_requirements(reqs)

        vulns = safety.check(
            packages=packages,
            db_mirror=False,
            cached=True,
            key=False,
            ignore_ids=[],
            proxy={}
        )
        self.assertEqual(len(vulns), 1)

        reqs = StringIO("insecure-package==0.1")
        packages = util.read_requirements(reqs)
        # make a second call to use the cache
        vulns = safety.check(
            packages=packages,
            db_mirror=False,
            cached=True,
            key=False,
            ignore_ids=[],
            proxy={}
        )
        self.assertEqual(len(vulns), 1)


class ReadRequirementsTestCase(unittest.TestCase):

    def test_unpinned_vcs_requirement(self):
        """
        https://github.com/pyupio/safety/issues/72
        """
        # this shouldn't raise an error
        content = StringIO("-e git+https://github.com/jdunck/python-unicodecsv#egg=unicodecsv")
        result = list(read_requirements(content))
        self.assertEqual(len(result), 0)

