import unittest
from unittest.mock import MagicMock, mock_open, patch
from pathlib import Path
from collections import defaultdict

from packaging.specifiers import SpecifierSet
from packaging.version import parse as parse_version

from safety.scan.ecosystems.python.main import (
    get_closest_ver, is_pinned_requirement)
from safety.scan.ecosystems.python.dependencies import (
    find_version,is_supported_by_parser, parse_requirement, read_requirements,
    read_dependencies, read_virtual_environment_dependencies,
    get_dependencies
)
from safety_schemas.models import PythonDependency, PythonSpecification, FileType
from safety.scan.ecosystems.base import InspectableFile
from dparse import filetypes


class TestEcosystemsPython(unittest.TestCase):

    def test_get_closest_ver(self):
        versions = ["1.0.0", "1.2.0", "2.0.0"]
        spec = SpecifierSet(">=1.0.0")
        version = "1.1.0"
        result = get_closest_ver(versions, version, spec)
        self.assertEqual(result, {'upper': parse_version("1.2.0"), 'lower': parse_version("1.0.0")})


    def test_is_pinned_requirement(self):
        spec = SpecifierSet("==1.0.0")
        self.assertTrue(is_pinned_requirement(spec))
        spec = SpecifierSet(">=1.0.0")
        self.assertFalse(is_pinned_requirement(spec))

    def test_find_version(self):
        specs = [MagicMock(spec=PythonSpecification)]
        specs[0].specifier = SpecifierSet("==1.0.0")
        self.assertEqual(find_version(specs), "1.0.0")

    def test_is_supported_by_parser(self):
        self.assertTrue(is_supported_by_parser("requirements.txt"))
        self.assertFalse(is_supported_by_parser("not_supported_file.md"))

    def test_parse_requirement(self):
        dep = "test_package>=1.0.0"
        found = "path/to/requirements.txt"
        result = parse_requirement(dep, found)
        self.assertIsInstance(result, PythonSpecification)
        self.assertEqual(result.found, Path(found).resolve())


if __name__ == '__main__':
    unittest.main()
