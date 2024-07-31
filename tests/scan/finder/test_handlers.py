import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from typing import Dict, List

from safety_schemas.models import Ecosystem, FileType
from safety.scan.finder.handlers import FileHandler, PythonFileHandler, SafetyProjectFileHandler, ECOSYSTEM_HANDLER_MAPPING

# Concrete subclass for testing
class TestableFileHandler(FileHandler):
    def download_required_assets(self, session):
        return {}

class TestFileHandler(unittest.TestCase):

    def setUp(self):
        self.handler = TestableFileHandler()
        self.handler.ecosystem = MagicMock(spec=Ecosystem)
        self.handler.ecosystem.file_types = [FileType.REQUIREMENTS_TXT]

    def test_cannot_handle(self):
        root = "/path/to"
        file_name = "unknown_file.xyz"
        include_files: Dict[FileType, List[Path]] = {}
        result = self.handler.can_handle(root, file_name, include_files)
        self.assertIsNone(result)

    def test_download_required_assets(self):
        self.assertEqual(self.handler.download_required_assets(None), {})


class TestPythonFileHandler(unittest.TestCase):

    def setUp(self):
        self.handler = PythonFileHandler()

    @patch('safety.safety.fetch_database')
    def test_download_required_assets(self, mock_fetch_database):
        session = MagicMock()
        self.handler.download_required_assets(session)
        self.assertEqual(mock_fetch_database.call_count, 2)


class TestSafetyProjectFileHandler(unittest.TestCase):

    def setUp(self):
        self.handler = SafetyProjectFileHandler()

    def test_download_required_assets(self):
        session = MagicMock()
        self.handler.download_required_assets(session)
        # Since the function does nothing, we just check it runs without error
        self.assertTrue(True)


class TestEcosystemHandlerMapping(unittest.TestCase):

    def test_mapping(self):
        self.assertIsInstance(ECOSYSTEM_HANDLER_MAPPING[Ecosystem.PYTHON](), PythonFileHandler)
        self.assertIsInstance(ECOSYSTEM_HANDLER_MAPPING[Ecosystem.SAFETY_PROJECT](), SafetyProjectFileHandler)


if __name__ == '__main__':
    unittest.main()
