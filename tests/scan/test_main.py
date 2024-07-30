import unittest
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path
from configparser import ConfigParser
from pydantic import ValidationError
from typing import Any, Dict, Set, Tuple

from safety.auth.utils import SafetyAuthSession
from safety.errors import SafetyError
from safety.scan.ecosystems.target import InspectableFileContext
from safety.scan.models import ScanExport, UnverifiedProjectModel
from safety.scan.main import (
    download_policy,
    load_unverified_project_from_config,
    save_project_info,
    load_policy_file,
    resolve_policy,
    save_report_as,
    process_files
)
from safety_schemas.models import FileType, PolicyFileModel, PolicySource, ConfigModel, Stage, ProjectModel, ScanType
import importlib
import time
class TestMainFunctions(unittest.TestCase):

    @patch('safety.scan.main.configparser.ConfigParser')
    def test_load_unverified_project_from_config(self, MockConfigParser):
        mock_config = MockConfigParser.return_value
        mock_config.get.side_effect = lambda section, option, fallback=None: {
            "id": "test_id",
            "url": "test_url",
            "name": "test_name"
        }.get(option, fallback)

        project_root = Path("/path/to/project")
        result = load_unverified_project_from_config(project_root)
        self.assertIsInstance(result, UnverifiedProjectModel)
        self.assertEqual(result.id, "test_id")
        self.assertEqual(result.url_path, "test_url")
        self.assertEqual(result.name, "test_name")

    @patch('builtins.open', new_callable=mock_open)
    @patch('safety.scan.main.configparser.ConfigParser')
    def test_save_project_info(self, MockConfigParser, mock_open):
        mock_config = MockConfigParser.return_value
        project = ProjectModel(id="test_id", url_path="test_url", name="test_name")
        project_path = Path("/path/to/project/.safety-project.ini")
        save_project_info(project, project_path)
        mock_config.read.assert_called_once_with(project_path)
        mock_open.assert_called_once_with(project_path, 'w')
        mock_config.write.assert_called_once()

    def test_resolve_policy(self):
        local_policy = MagicMock()
        cloud_policy = MagicMock()
        result = resolve_policy(local_policy, cloud_policy)
        self.assertEqual(result, cloud_policy)

        result = resolve_policy(local_policy, None)
        self.assertEqual(result, local_policy)

        result = resolve_policy(None, cloud_policy)
        self.assertEqual(result, cloud_policy)

        result = resolve_policy(None, None)
        self.assertIsNone(result)


    @patch('safety.scan.main.InspectableFileContext')
    def test_process_files(self, MockInspectableFileContext):
        paths = {
            "requirements.txt": {Path("/path/to/requirements.txt")},
        }
        config = MagicMock()
        mock_file = MockInspectableFileContext.return_value.__enter__.return_value
        mock_file.file_type = FileType.REQUIREMENTS_TXT

        result = list(process_files(paths, config))
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], Tuple)
        self.assertEqual(result[0][0], Path("/path/to/requirements.txt"))

if __name__ == '__main__':
    unittest.main()