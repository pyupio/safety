import unittest
from unittest.mock import MagicMock, mock_open, patch
from pathlib import Path
from typer import FileTextWrite
from safety_schemas.models import Ecosystem, FileType
from safety.scan.ecosystems.python.main import PythonFile
from safety.scan.ecosystems.target import InspectableFileContext, TargetFile

class TestInspectableFileContext(unittest.TestCase):
    def setUp(self):
        self.file_path = Path("/fake/path/to/requirements.txt")
        self.file_type = MagicMock(spec=FileType)
        self.file_type.ecosystem = Ecosystem.PYTHON

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    def test_enter_success(self, mock_open):
        with InspectableFileContext(self.file_path, self.file_type) as inspectable_file:
            self.assertIsInstance(inspectable_file, PythonFile)
            mock_open.assert_called_once_with(self.file_path, mode='r+')

    @patch("builtins.open", new_callable=mock_open)
    def test_enter_failure(self, mock_open):
        mock_open.side_effect = IOError("Permission denied")
        with InspectableFileContext(self.file_path, self.file_type) as inspectable_file:
            self.assertIsNone(inspectable_file)
            mock_open.assert_called_once_with(self.file_path, mode='r+')

    @patch("builtins.open", new_callable=mock_open, read_data="data")
    def test_exit(self, mock_open):
        with InspectableFileContext(self.file_path, self.file_type) as inspectable_file:
            pass
        inspectable_file.file.close.assert_called_once()

class TestTargetFile(unittest.TestCase):
    def setUp(self):
        self.file = MagicMock(spec=FileTextWrite)
        self.file_type_python = MagicMock(spec=FileType)
        self.file_type_python.ecosystem = Ecosystem.PYTHON

    def test_create_python_file(self):
        result = TargetFile.create(file_type=self.file_type_python, file=self.file)
        self.assertIsInstance(result, PythonFile)

    def test_create_unsupported_ecosystem(self):
        file_type_unknown = MagicMock(spec=FileType)
        file_type_unknown.ecosystem = "UNKNOWN"
        file_type_unknown.value = "unsupported_value"
        with self.assertRaises(ValueError):
            TargetFile.create(file_type=file_type_unknown, file=self.file)

if __name__ == '__main__':
    unittest.main()
