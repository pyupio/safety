from datetime import date, timedelta
from unittest.mock import MagicMock

from packaging.specifiers import SpecifierSet
from safety_schemas.models import (
    FileType,
    IgnoreCodes,
    IgnoredItemDetail,
    PythonSpecification,
)

from safety.scan.ecosystems.python.main import ignore_vuln_if_needed


class TestMain:
    def test_ignore_vuln_not_bound_to_package_version(self):
        """
        Regression test for issue #907.

        A manual ignore with no recorded specifications must not silently
        suppress a vulnerability in a different package version.
        """
        vuln_id = "VULN-TEST-0001"
        ignore_vulns = {
            vuln_id: IgnoredItemDetail(
                code=IgnoreCodes.manual,
                reason="ignore for pkg=1.0 only",
                expires=None,
                specifications=None,
            )
        }

        dep = MagicMock()
        dep.name = "examplepkg"
        dep.version = "2.0"

        specification = PythonSpecification("examplepkg==2.0")

        ignore_vuln_if_needed(
            dependency=dep,
            file_type=FileType.REQUIREMENTS_TXT,
            vuln_id=vuln_id,
            cve=None,
            ignore_vulns=ignore_vulns,
            ignore_unpinned=False,
            ignore_environment=False,
            specification=specification,
            ignore_severity=[],
        )

        assert vuln_id not in ignore_vulns

    def test_ignore_vuln_bound_to_other_specifier_is_dropped(self):
        """An ignore bound to pkg==1.0 must not suppress pkg==2.0."""
        vuln_id = "VULN-TEST-0002"
        ignore_vulns = {
            vuln_id: IgnoredItemDetail(
                code=IgnoreCodes.manual,
                reason="ignore for pkg=1.0 only",
                expires=date.today() + timedelta(days=30),
                specifications={"==1.0"},
            )
        }

        dep = MagicMock()
        dep.name = "examplepkg"
        dep.version = "2.0"

        specification = PythonSpecification("examplepkg==2.0")

        ignore_vuln_if_needed(
            dependency=dep,
            file_type=FileType.REQUIREMENTS_TXT,
            vuln_id=vuln_id,
            cve=None,
            ignore_vulns=ignore_vulns,
            ignore_unpinned=False,
            ignore_environment=False,
            specification=specification,
            ignore_severity=[],
        )

        assert vuln_id not in ignore_vulns

    def test_ignore_vuln_without_expiry_does_not_suppress(self):
        """
        Regression test for issue #907 - an unset 'expires' must not cause
        indefinite suppression.
        """
        vuln_id = "VULN-TEST-0003"
        ignore_vulns = {
            vuln_id: IgnoredItemDetail(
                code=IgnoreCodes.manual,
                reason="no expiry set",
                expires=None,
                specifications={"==1.0"},
            )
        }

        dep = MagicMock()
        dep.name = "examplepkg"
        dep.version = "1.0"

        specification = PythonSpecification("examplepkg==1.0")

        ignore_vuln_if_needed(
            dependency=dep,
            file_type=FileType.REQUIREMENTS_TXT,
            vuln_id=vuln_id,
            cve=None,
            ignore_vulns=ignore_vulns,
            ignore_unpinned=False,
            ignore_environment=False,
            specification=specification,
            ignore_severity=[],
        )

        assert vuln_id not in ignore_vulns

    def test_ignore_vuln_with_future_expiry_still_suppresses(self):
        """
        Regression - an explicit future expiry on a matching specifier keeps
        the ignore.
        """
        vuln_id = "VULN-TEST-0004"
        ignore_vulns = {
            vuln_id: IgnoredItemDetail(
                code=IgnoreCodes.manual,
                reason="still valid",
                expires=date.today() + timedelta(days=30),
                specifications={"==1.0"},
            )
        }

        dep = MagicMock()
        dep.name = "examplepkg"
        dep.version = "1.0"

        specification = PythonSpecification("examplepkg==1.0")

        ignore_vuln_if_needed(
            dependency=dep,
            file_type=FileType.REQUIREMENTS_TXT,
            vuln_id=vuln_id,
            cve=None,
            ignore_vulns=ignore_vulns,
            ignore_unpinned=False,
            ignore_environment=False,
            specification=specification,
            ignore_severity=[],
        )

        # Suppression is signalled by the early return, which leaves the entry
        # in the dict. get_vulnerability() then reads it back as ignored=True.
        assert vuln_id in ignore_vulns