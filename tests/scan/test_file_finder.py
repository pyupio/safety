# type: ignore
import unittest
from unittest.mock import patch
from pathlib import Path

from safety.scan.finder.file_finder import FileFinder, should_exclude


class TestShouldExclude(unittest.TestCase):
    def test_should_exclude(self):
        excludes = {Path("/exclude"), Path("/file.py")}
        self.assertTrue(should_exclude(excludes, Path("/exclude/path")))
        self.assertTrue(should_exclude(excludes, Path("/file.py")))
        self.assertFalse(should_exclude(excludes, Path("/absolute/path")))


class TestFileFinder(unittest.TestCase):
    @patch.object(Path, "glob")
    @patch("os.walk")
    def test_process_directory(self, mock_os_walk, mock_glob):
        # Mock the os.walk function to return a fake directory structure
        mock_os_walk.return_value = [
            ("/root", ["dir1", "dir2"], ["file1", "file2"]),
            ("/root/dir1", [], ["file3", "file4"]),
            ("/root/dir2", [], ["file5", "file6"]),
        ]

        # Mock the Path.glob method to simulate the exclusion patterns
        mock_glob.return_value = [Path("/root/dir1")]

        file_finder = FileFinder(max_level=1, ecosystems=[], target=Path("/root"))
        dir_path, files = file_finder.process_directory("/root")

        self.assertEqual(dir_path, "/root")
        self.assertEqual(
            len(files), 0
        )  # No files should be found as we didn't mock the handlers

    @patch.object(Path, "glob")
    @patch("os.walk")
    def test_search(self, mock_os_walk, mock_glob):
        # Mock the os.walk function to return a fake directory structure
        mock_os_walk.return_value = [
            ("/root", ["dir1", "dir2"], ["file1", "file2"]),
            ("/root/dir1", [], ["file3", "file4"]),
            ("/root/dir2", [], ["file5", "file6"]),
        ]

        # Mock the Path.glob method to simulate the exclusion patterns
        mock_glob.return_value = [Path("/root/dir1")]

        file_finder = FileFinder(max_level=1, ecosystems=[], target=Path("/root"))
        dir_path, files = file_finder.search()

        self.assertEqual(dir_path, Path("/root"))
        self.assertEqual(
            len(files), 0
        )  # No files should be found as we didn't mock the handlers
