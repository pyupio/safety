import unittest
from subprocess import CompletedProcess

import packaging
from packaging.specifiers import SpecifierSet

from safety.errors import InvalidRequirementError
from safety.models import SafetyRequirement
from safety.models.requirements import is_pinned_requirement
from safety.models.tools import ToolResult


class TestIsPinnedRequirement(unittest.TestCase):
    """Tests for is_pinned_requirement function"""

    def test_pinned_with_double_equals(self):
        """Test that == operator with specific version is recognized as pinned"""
        spec = SpecifierSet("==1.2.3")
        self.assertTrue(is_pinned_requirement(spec))

    def test_pinned_with_triple_equals(self):
        """Test that === operator is recognized as pinned"""
        spec = SpecifierSet("===1.2.3")
        self.assertTrue(is_pinned_requirement(spec))

    def test_not_pinned_with_wildcard(self):
        """Test that == with wildcard is not considered pinned"""
        spec = SpecifierSet("==1.2.*")
        self.assertFalse(is_pinned_requirement(spec))

    def test_not_pinned_with_greater_than(self):
        """Test that >= operator is not considered pinned"""
        spec = SpecifierSet(">=1.2.3")
        self.assertFalse(is_pinned_requirement(spec))

    def test_not_pinned_with_less_than(self):
        """Test that <= operator is not considered pinned"""
        spec = SpecifierSet("<=1.2.3")
        self.assertFalse(is_pinned_requirement(spec))

    def test_not_pinned_with_compatible_release(self):
        """Test that ~= operator is not considered pinned"""
        spec = SpecifierSet("~=1.2.3")
        self.assertFalse(is_pinned_requirement(spec))

    def test_not_pinned_with_multiple_specifiers(self):
        """Test that multiple specifiers are not considered pinned"""
        spec = SpecifierSet(">=1.2.3,<2.0.0")
        self.assertFalse(is_pinned_requirement(spec))

    def test_not_pinned_with_empty_specifier(self):
        """Test that empty specifier is not considered pinned"""
        spec = SpecifierSet("")
        self.assertFalse(is_pinned_requirement(spec))

    def test_not_pinned_with_none(self):
        """Test that None specifier is not considered pinned"""
        self.assertFalse(is_pinned_requirement(None))


class TestSafetyRequirement(unittest.TestCase):

    @unittest.skipIf(tuple(map(int, packaging.__version__.split("."))) < (22, 0),
                     "not validated in these versions")
    def test_with_invalid_input(self):
        invalid_inputs = [
            'django*',
            'django>=python>=3.6',
            'numpy>=3.3python>=3.6',
            '',
            '\n'
        ]

        for i_input in invalid_inputs:
            with self.assertRaises(InvalidRequirementError):
                SafetyRequirement(i_input)

    def test_valid_requirement_simple(self):
        """Test creating a valid simple requirement"""
        req = SafetyRequirement("django==3.2.0")
        self.assertIsNotNone(req)

    def test_valid_requirement_with_version_range(self):
        """Test creating a valid requirement with version range"""
        req = SafetyRequirement("flask>=2.0.0")
        self.assertIsNotNone(req)

    def test_valid_requirement_with_extras(self):
        """Test creating a valid requirement with extras"""
        req = SafetyRequirement("requests[security]>=2.25.0")
        self.assertIsNotNone(req)


class TestToolResult(unittest.TestCase):
    """Tests for ToolResult dataclass"""

    def test_tool_result_initialization(self):
        """Test ToolResult can be initialized with required fields"""
        process = CompletedProcess(args=["test"], returncode=0)
        result = ToolResult(process=process, duration_ms=100, tool_path="/usr/bin/test")

        self.assertEqual(result.process, process)
        self.assertEqual(result.duration_ms, 100)
        self.assertEqual(result.tool_path, "/usr/bin/test")

    def test_tool_result_with_failed_process(self):
        """Test ToolResult with failed process"""
        process = CompletedProcess(args=["test"], returncode=1, stdout="error", stderr="failed")
        result = ToolResult(process=process, duration_ms=50, tool_path="/usr/bin/test")

        self.assertEqual(result.process.returncode, 1)
        self.assertEqual(result.duration_ms, 50)
