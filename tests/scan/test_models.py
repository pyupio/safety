import unittest
from pathlib import Path
from typing import Optional
from enum import Enum
from pydantic.dataclasses import dataclass
from safety.scan.models import FormatMixin, ScanOutput, ScanExport, SystemScanOutput, SystemScanExport, UnverifiedProjectModel

class TestFormatMixin(unittest.TestCase):

    def test_is_format(self):
        class TestEnum(Enum):
            FORMAT_A = "format_a"
            FORMAT_B = "format_b@1.0"

        self.assertTrue(FormatMixin.is_format(TestEnum.FORMAT_A, TestEnum.FORMAT_A))
        self.assertFalse(FormatMixin.is_format(TestEnum.FORMAT_A, TestEnum.FORMAT_B))
        self.assertTrue(FormatMixin.is_format(TestEnum.FORMAT_B, TestEnum.FORMAT_B))
        self.assertFalse(FormatMixin.is_format(None, TestEnum.FORMAT_A))
        self.assertTrue(FormatMixin.is_format(TestEnum.FORMAT_B, TestEnum("format_b@1.0")))

    def test_version(self):
        class TestEnum(FormatMixin, str, Enum):
            FORMAT_A = "format_a"
            FORMAT_B = "format_b@1.0"

        self.assertIsNone(TestEnum.FORMAT_A.version)
        self.assertEqual(TestEnum.FORMAT_B.version, "1.0")


class TestScanOutput(unittest.TestCase):

    def test_is_silent(self):
        self.assertTrue(ScanOutput.JSON.is_silent())
        self.assertTrue(ScanOutput.SPDX.is_silent())
        self.assertTrue(ScanOutput.SPDX_2_3.is_silent())
        self.assertTrue(ScanOutput.SPDX_2_2.is_silent())
        self.assertTrue(ScanOutput.HTML.is_silent())
        self.assertFalse(ScanOutput.SCREEN.is_silent())
        self.assertFalse(ScanOutput.NONE.is_silent())


class TestScanExport(unittest.TestCase):

    def test_get_default_file_name(self):
        tag = 123456
        self.assertEqual(ScanExport.JSON.get_default_file_name(tag), f"safety-report-{tag}.json")
        self.assertEqual(ScanExport.SPDX.get_default_file_name(tag), f"safety-report-spdx-{tag}.json")
        self.assertEqual(ScanExport.SPDX_2_3.get_default_file_name(tag), f"safety-report-spdx-{tag}.json")
        self.assertEqual(ScanExport.SPDX_2_2.get_default_file_name(tag), f"safety-report-spdx-{tag}.json")
        self.assertEqual(ScanExport.HTML.get_default_file_name(tag), f"safety-report-{tag}.html")
        with self.assertRaises(ValueError):
            ScanExport("unsupported").get_default_file_name(tag)


class TestSystemScanOutput(unittest.TestCase):

    def test_is_silent(self):
        self.assertTrue(SystemScanOutput.JSON.is_silent())
        self.assertFalse(SystemScanOutput.SCREEN.is_silent())


class TestSystemScanExport(unittest.TestCase):

    def test_system_scan_export(self):
        self.assertEqual(SystemScanExport.JSON.value, "json")


class TestUnverifiedProjectModel(unittest.TestCase):

    def test_unverified_project_model(self):
        project = UnverifiedProjectModel(
            id="test_id",
            project_path=Path("/path/to/project"),
            created=True,
            name="test_name",
            url_path="http://test.url"
        )
        self.assertEqual(project.id, "test_id")
        self.assertEqual(project.project_path, Path("/path/to/project"))
        self.assertTrue(project.created)
        self.assertEqual(project.name, "test_name")
        self.assertEqual(project.url_path, "http://test.url")


if __name__ == '__main__':
    unittest.main()
