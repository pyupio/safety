import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from safety_schemas.models import Ecosystem, FileType
from safety.scan.finder.file_finder import FileFinder, should_exclude
from safety.scan.finder.handlers import FileHandler

class TestShouldExclude(unittest.TestCase):
    def test_should_exclude_absolute(self):
        excludes = {Path("/path/to/exclude")}
        to_analyze = Path("/path/to/exclude/file.txt")
        self.assertTrue(should_exclude(excludes, to_analyze))

    def test_should_exclude_relative(self):
        excludes = {Path("exclude")}
        to_analyze = Path("exclude/file.txt").resolve()
        self.assertTrue(should_exclude(excludes, to_analyze))

    def test_should_not_exclude(self):
        excludes = {Path("/path/to/exclude")}
        to_analyze = Path("/path/to/include/file.txt")
        self.assertFalse(should_exclude(excludes, to_analyze))

class TestFileFinder(unittest.TestCase):
    def setUp(self):
        self.max_level = 2
        self.ecosystems = [Ecosystem.PYTHON]
        self.target = Path("/path/to/target")
        self.console = MagicMock()
        self.live_status = MagicMock()

        self.handler = MagicMock(spec=FileHandler)
        self.handler.can_handle.return_value = FileType.REQUIREMENTS_TXT
        self.handlers = {self.handler}

    @patch('safety.scan.finder.file_finder.os.walk')
    @patch('safety.scan.finder.handlers.ECOSYSTEM_HANDLER_MAPPING', {'PYTHON': lambda: self.handler})
    def test_process_directory(self, mock_os_walk):
        mock_os_walk.return_value = [
            ("/path/to/target", ["subdir"], ["file1.txt", "file2.py"]),
            ("/path/to/target/subdir", [], ["file3.txt"])
        ]

        finder = FileFinder(
            max_level=self.max_level, ecosystems=self.ecosystems,
            target=self.target, console=self.console,
            live_status=self.live_status, handlers=self.handlers
        )

        dir_path, files = finder.process_directory(self.target)
        self.assertEqual(str(dir_path), str(self.target))  # Convert dir_path to string
        self.assertIn(FileType.REQUIREMENTS_TXT.value, files)  # Use the actual file type
        self.assertEqual(len(files[FileType.REQUIREMENTS_TXT.value]), 3)  # Adjust based on the actual expected filetype

    @patch('safety.scan.finder.file_finder.os.walk')
    @patch('safety.scan.finder.handlers.ECOSYSTEM_HANDLER_MAPPING', {'PYTHON': lambda: self.handler})
    def test_search(self, mock_os_walk):
        mock_os_walk.return_value = [
            ("/path/to/target", ["subdir"], ["file1.txt", "file2.py"]),
            ("/path/to/target/subdir", [], ["file3.txt"])
        ]

        finder = FileFinder(
            max_level=self.max_level, ecosystems=self.ecosystems,
            target=self.target, console=self.console,
            live_status=self.live_status, handlers=self.handlers
        )

        dir_path, files = finder.search()
        self.assertEqual(str(dir_path), str(self.target))  # Convert dir_path to string
        self.assertIn(FileType.REQUIREMENTS_TXT.value, files)  # Use the actual file type
        self.assertEqual(len(files[FileType.REQUIREMENTS_TXT.value]), 3)  # Adjust based on the actual expected filetype

    def test_should_exclude(self):
        excludes = {Path("/exclude/this")}
        path_to_analyze = Path("/exclude/this/file")
        self.assertTrue(should_exclude(excludes, path_to_analyze))

        path_to_analyze = Path("/do/not/exclude/this/file")
        self.assertFalse(should_exclude(excludes, path_to_analyze))

if __name__ == '__main__':
    unittest.main()
