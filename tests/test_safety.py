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
from unittest.mock import Mock, patch

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

    @patch("safety.safety.get_licenses")
    def test_license_bare(self, get_licenses):
        runner = CliRunner()

        dirname = os.path.dirname(__file__)
        with open(os.path.join(dirname, "test_db", "licenses.json")) as f:
            licenses_db = json.loads(f.read())
        get_licenses.return_value = licenses_db
        reqs_path = os.path.join(dirname, "reqs_4.txt")

        result = runner.invoke(cli.cli, ['license', '--file', reqs_path, '--bare', '--db', 'licenses.json'])
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.output, 'BSD-3-Clause\n')

    @patch("safety.safety.get_licenses")
    def test_license_json(self, get_licenses):
        runner = CliRunner()

        dirname = os.path.dirname(__file__)
        with open(os.path.join(dirname, "test_db", "licenses.json")) as f:
            licenses_db = json.loads(f.read())
        get_licenses.return_value = licenses_db
        reqs_path = os.path.join(dirname, "reqs_4.txt")

        result = runner.invoke(cli.cli, ['license', '--file', reqs_path, '--json', '--db', 'licenses.json'])
        expected_result = json.dumps(
            [{
                "license": "BSD-3-Clause",
                "package": "django",
                "version": "1.11"
            }],
            indent=4, sort_keys=True
        )
        self.assertEqual(result.exit_code, 0)
        self.assertMultiLineEqual(result.output.rstrip(), expected_result)


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
        assert 'free DB (updated once a month)' == formatter.get_used_db(key=None, db='')
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
                cvssv2=None,
                cvssv3=None,
            ),
        ]
        full_report = formatter.SheetReport.render(
            vulns, full=True, checked_packages=5, used_db='test DB')
        self.assertMultiLineEqual(full_report + "\n", textwrap.dedent(r"""
            +==============================================================================+
            |                                                                              |
            |                               /$$$$$$            /$$                         |
            |                              /$$__  $$          | $$                         |
            |           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
            |          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
            |         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
            |          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
            |          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
            |         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
            |                                                          /$$  | $$           |
            |                                                         |  $$$$$$/           |
            |  by pyup.io                                              \______/            |
            |                                                                              |
            +==============================================================================+
            | REPORT                                                                       |
            | checked 5 packages, using test DB                                            |
            +============================+===========+==========================+==========+
            | package                    | installed | affected                 | ID       |
            +============================+===========+==========================+==========+
            | libfoo                     | 1.9.3     | <2.0.0                   |     1234 |
            +==============================================================================+
            | libfoo prior to version 2.0.0 had a vulnerability blah blah blah blah blah   |
            | blah blah blah blah blah blah blah blah blah blah.                           |
            |                                                                              |
            | All users are urged to upgrade please.                                       |
            +==============================================================================+
            """.lstrip('\n')))


class TestSafety(unittest.TestCase):
    def test_review_from_file(self):
        dirname = os.path.dirname(__file__)
        path_to_report = os.path.join(dirname, "test_db", "example_report.json")
        with open(path_to_report) as insecure:
            input_vulns = read_vulnerabilities(insecure)

        vulns = safety.review(input_vulns)
        self.assertEqual(len(vulns), 3)

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
            proxy={},
        )
        self.assertEqual(len(vulns), 2)

    def test_check_from_file_with_hash_pins(self):
        reqs = StringIO(("Django==1.8.1 "
                         "--hash=sha256:c6c7e7a961e2847d050d214ca96dc3167bb5f2b25cd5c6cb2eea96e1717f4ade"))
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
            proxy={},
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
            proxy={},
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
            proxy={},
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
            proxy={},
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
            proxy={},
        )
        self.assertEqual(len(vulns), 1)

    def test_get_packages_licenses(self):
        reqs = StringIO("Django==1.8.1\n\rinvalid==1.0.0")
        packages = util.read_requirements(reqs)
        licenses_db = safety.get_licenses(
            db_mirror=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "test_db"
            ),
            cached=False,
            key="foobarqux",
            proxy={},
        )
        self.assertIn("licenses", licenses_db)
        self.assertIn("packages", licenses_db)
        self.assertIn("BSD-3-Clause", licenses_db['licenses'])
        self.assertIn("django", licenses_db['packages'])

        pkg_licenses = util.get_packages_licenses(packages, licenses_db)

        self.assertIsInstance(pkg_licenses, list)
        for pkg_license in pkg_licenses:
            license = pkg_license['license']
            version = pkg_license['version']
            if pkg_license['package'] == 'django':
                self.assertEqual(license, 'BSD-3-Clause')
                self.assertEqual(version, '1.8.1')
            elif pkg_license['package'] == 'invalid':
                self.assertEqual(license, 'N/A')
                self.assertEqual(version, '1.0.0')
            else:
                raise AssertionError(
                    "unexpected package '" + pkg_license['package'] + "' was found"
                )

    def test_get_packages_licenses_without_api_key(self):
        from safety.errors import InvalidKeyError

        # without providing an API-KEY 
        with self.assertRaises(InvalidKeyError) as error:
            safety.get_licenses(
                db_mirror=False,
                cached=False,
                proxy={},
                key=None
            )
        db_generic_exception = error.exception
        self.assertEqual(str(db_generic_exception), 'The API-KEY was not provided.')

    @patch("safety.safety.requests")
    def test_get_packages_licenses_with_invalid_api_key(self, requests):
        from safety.errors import InvalidKeyError

        mock = Mock()
        mock.status_code = 403
        requests.get.return_value = mock

        # proving an invalid API-KEY
        with self.assertRaises(InvalidKeyError):
            safety.get_licenses(
                db_mirror=False,
                cached=False,
                proxy={},
                key="INVALID"
            )

    @patch("safety.safety.requests")
    def test_get_packages_licenses_db_fetch_error(self, requests):
        from safety.errors import DatabaseFetchError

        mock = Mock()
        mock.status_code = 500
        requests.get.return_value = mock

        with self.assertRaises(DatabaseFetchError):
            safety.get_licenses(
                db_mirror=False,
                cached=False,
                proxy={},
                key="MY-VALID-KEY"
            )
    
    def test_get_packages_licenses_with_invalid_db_file(self):
        from safety.errors import DatabaseFileNotFoundError

        with self.assertRaises(DatabaseFileNotFoundError):
            safety.get_licenses(
                db_mirror='/my/invalid/path',
                cached=False,
                proxy={},
                key=None
            )

    @patch("safety.safety.requests")
    def test_get_packages_licenses_very_often(self, requests):
        from safety.errors import TooManyRequestsError

        # if the request is made too often, an 429 error is raise by PyUp.io
        mock = Mock()
        mock.status_code = 429
        requests.get.return_value = mock

        with self.assertRaises(TooManyRequestsError):
            safety.get_licenses(
                db_mirror=False,
                cached=False,
                proxy={},
                key="MY-VALID-KEY"
            )

    @patch("safety.safety.requests")
    def test_get_cached_packages_licenses(self, requests):
        import copy
        from safety.constants import CACHE_FILE

        licenses_db = {
            "licenses": {
                "BSD-3-Clause": 2
            },
            "packages": {
                "django": [
                    {
                        "start_version": "0.0",
                        "license_id": 2
                    }
                ]
            }
        }
        original_db = copy.deepcopy(licenses_db)

        mock = Mock()
        mock.json.return_value = licenses_db
        mock.status_code = 200
        requests.get.return_value = mock

        # lets clear the cache first
        try:
            with open(CACHE_FILE, 'w') as f:
                f.write(json.dumps({}))
        except Exception:
            pass
        
        # In order to cache the db (and get), we must set cached as True
        response = safety.get_licenses(
            db_mirror=False,
            cached=True,
            proxy={},
            key="MY-VALID-KEY"
        )
        self.assertEqual(response, licenses_db)

        # now we should have the db in cache
        # changing the "live" db to test if we are getting the cached db
        licenses_db['licenses']['BSD-3-Clause'] = 123

        resp = safety.get_licenses(
            db_mirror=False,
            cached=True,
            proxy={},
            key="MY-VALID-KEY"
        )
        
        self.assertNotEqual(resp, licenses_db)
        self.assertEqual(resp, original_db)

    def test_report_licenses_bare(self):
        from safety.formatter import license_report

        reqs = StringIO("Django==1.8.1\n\rinexistent==1.0.0")
        packages = util.read_requirements(reqs)

        # Using DB: test.test_db.licenses.json
        licenses_db = safety.get_licenses(
            db_mirror=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "test_db"
            ),
            cached=False,
            key=None,
            proxy={},
        )

        pkgs_licenses = util.get_packages_licenses(packages, licenses_db)
        output_report = license_report(
            packages=packages,
            licenses=pkgs_licenses,
            json_report=False,
            bare_report=True
        )
        self.assertEqual(output_report, "BSD-3-Clause")

    def test_report_licenses_json(self):
        from safety.formatter import license_report

        reqs = StringIO("Django==1.8.1\n\rinexistent==1.0.0")
        packages = util.read_requirements(reqs)

        # Using DB: test.test_db.licenses.json
        licenses_db = safety.get_licenses(
            db_mirror=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "test_db"
            ),
            cached=False,
            key=None,
            proxy={},
        )

        pkgs_licenses = util.get_packages_licenses(packages, licenses_db)
        output_report = license_report(
            packages=packages,
            licenses=pkgs_licenses,
            json_report=True,
            bare_report=False
        )

        expected_result = json.dumps(
            [{
                "license": "BSD-3-Clause",
                "package": "django",
                "version": "1.8.1"
            },
            {
                "license": "N/A",
                "package": "inexistent",
                "version": "1.0.0"
            }],
            indent=4, sort_keys=True
        )
        # Packages without license are reported as "N/A"
        self.assertEqual(output_report.rstrip(), expected_result)


class ReadRequirementsTestCase(unittest.TestCase):

    def test_unpinned_vcs_requirement(self):
        """
        https://github.com/pyupio/safety/issues/72
        """
        # this shouldn't raise an error
        content = StringIO("-e git+https://github.com/jdunck/python-unicodecsv#egg=unicodecsv")
        result = list(read_requirements(content))
        self.assertEqual(len(result), 0)

    def test_recursive_requirement(self):
        """
        https://github.com/pyupio/safety/issues/132
        """
        # this should find 2 bad packages
        dirname = os.path.dirname(__file__)
        test_filename = os.path.join(dirname, "reqs_1.txt")
        with open(test_filename) as fh:
            result = list(read_requirements(fh, resolve=True))
        self.assertEqual(len(result), 2)
