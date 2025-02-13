import os

from unittest.mock import Mock, patch
from safety.scan.finder.handlers import PythonFileHandler

@patch('safety.safety.fetch_database')
def test_download_required_assets(mock_fetch_database):
    handler = PythonFileHandler()
    session = Mock()

    os.environ["SAFETY_DB_DIR"] = "/path/to/db"
    handler.download_required_assets(session)

    _, kwargs = mock_fetch_database.call_args

    assert kwargs['db'] == "/path/to/db"

@patch('safety.safety.fetch_database')
def test_download_required_assets_no_db_dir(mock_fetch_database):
    handler = PythonFileHandler()
    session = Mock()

    if "SAFETY_DB_DIR" in os.environ:
        del os.environ["SAFETY_DB_DIR"]
    handler.download_required_assets(session)

    _, kwargs = mock_fetch_database.call_args

    assert kwargs['db'] == False
