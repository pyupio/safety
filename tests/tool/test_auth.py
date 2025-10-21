import unittest
import pytest
import json
import base64
from unittest.mock import MagicMock, patch

import typer
from safety.tool.auth import index_credentials, build_index_url
from safety.tool.constants import PYPI_PUBLIC_REPOSITORY_URL


@pytest.mark.unit
class TestIndexCredentials(unittest.TestCase):
    """
    Test cases for index_credentials function.
    """

    def test_index_credentials_with_full_auth_object(self):
        """
        Test index_credentials when ctx.obj.auth is fully populated with token and api_key.
        """
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = MagicMock()
        ctx.obj.auth.client.token = {"access_token": "test_token"}
        ctx.obj.auth.client.api_key = "test_api_key"
        ctx.obj.project.id = "test_project_id"

        result = index_credentials(ctx)

        decoded = json.loads(
            base64.urlsafe_b64decode(result.encode("utf-8")).decode("utf-8")
        )

        self.assertEqual(decoded["version"], "1.0")
        self.assertEqual(decoded["access_token"], "test_token")
        self.assertEqual(decoded["api_key"], "test_api_key")
        self.assertEqual(decoded["project_id"], "test_project_id")

    def test_index_credentials_with_missing_token(self):
        """
        Test index_credentials when token is None but api_key is present.
        """
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = MagicMock()
        ctx.obj.auth.client.token = None
        ctx.obj.auth.client.api_key = "test_api_key"
        ctx.obj.project.id = "test_project_id"

        result = index_credentials(ctx)

        decoded = json.loads(
            base64.urlsafe_b64decode(result.encode("utf-8")).decode("utf-8")
        )
        self.assertEqual(decoded["version"], "1.0")
        self.assertIsNone(decoded["access_token"])
        self.assertEqual(decoded["api_key"], "test_api_key")
        self.assertEqual(decoded["project_id"], "test_project_id")

    def test_index_credentials_with_missing_api_key(self):
        """
        Test index_credentials when api_key is None but token is present.
        """
        ctx = MagicMock(spec=typer.Context)
        ctx.obj = MagicMock()
        ctx.obj.auth.client.token = {"access_token": "test_token"}
        ctx.obj.auth.client.api_key = None
        ctx.obj.project.id = "test_project_id"

        result = index_credentials(ctx)

        decoded = json.loads(
            base64.urlsafe_b64decode(result.encode("utf-8")).decode("utf-8")
        )

        self.assertEqual(decoded["version"], "1.0")
        self.assertEqual(decoded["access_token"], "test_token")
        self.assertIsNone(decoded["api_key"])
        self.assertEqual(decoded["project_id"], "test_project_id")

    def test_index_credentials_with_no_auth(self):
        """
        Test index_credentials when ctx.obj.auth is None.
        """

        ctx = MagicMock(spec=typer.Context)
        ctx.obj = MagicMock()
        ctx.obj.auth = None
        ctx.obj.project.id = "test_project_id"

        result = index_credentials(ctx)

        decoded = json.loads(
            base64.urlsafe_b64decode(result.encode("utf-8")).decode("utf-8")
        )

        self.assertEqual(decoded["version"], "1.0")
        self.assertIsNone(decoded["access_token"])
        self.assertIsNone(decoded["api_key"])
        self.assertEqual(decoded["project_id"], "test_project_id")

    def test_index_credentials_with_no_project(self):
        """
        Test index_credentials when ctx.obj.project is None.
        """

        ctx = MagicMock(spec=typer.Context)
        ctx.obj = MagicMock()
        ctx.obj.auth.client.token = {"access_token": "test_token"}
        ctx.obj.auth.client.api_key = "test_api_key"
        ctx.obj.project = None

        result = index_credentials(ctx)

        decoded = json.loads(
            base64.urlsafe_b64decode(result.encode("utf-8")).decode("utf-8")
        )

        self.assertEqual(decoded["version"], "1.0")
        self.assertEqual(decoded["access_token"], "test_token")
        self.assertEqual(decoded["api_key"], "test_api_key")
        self.assertIsNone(decoded["project_id"])

    def test_index_credentials_correct_encoding(self):
        """
        Test that index_credentials correctly encodes the credentials in base64url format.
        """

        ctx = MagicMock(spec=typer.Context)
        ctx.obj = MagicMock()
        ctx.obj.auth.client.token = {"access_token": "test_token"}
        ctx.obj.auth.client.api_key = "test_api_key"
        ctx.obj.project.id = "test_project_id"

        result = index_credentials(ctx)

        expected_json = json.dumps(
            {
                "version": "1.0",
                "access_token": "test_token",
                "api_key": "test_api_key",
                "project_id": "test_project_id",
            }
        )

        expected_encoded = base64.urlsafe_b64encode(
            expected_json.encode("utf-8")
        ).decode("utf-8")

        self.assertEqual(result, expected_encoded)


@pytest.mark.unit
class TestBuildIndexUrl:
    """
    Test suite for build_index_url
    """

    def setup_method(self):
        self.ctx = MagicMock(spec=typer.Context)
        self.ctx.obj = MagicMock()

    def test_build_index_url_injects_and_defaults(self):
        """
        It injects user:<b64>@ into netloc and defaults to PYPI_PUBLIC_REPOSITORY_URL when index_url is None.
        """
        with patch(
            "safety.tool.auth.index_credentials", return_value="mock_creds"
        ) as mock_ic:
            # explicit custom URL
            custom_url = "https://pkgs.safetycli.com/repository/safety-cybersecurity/project/safety/pypi/simple/"
            result_custom = build_index_url(self.ctx, custom_url, "pypi")
            assert (
                result_custom
                == "https://user:mock_creds@pkgs.safetycli.com/repository/safety-cybersecurity/project/safety/pypi/simple/"
            )

            # default to PYPI_PUBLIC_REPOSITORY_URL
            result_default = build_index_url(self.ctx, None, "pypi")
            expected_host = PYPI_PUBLIC_REPOSITORY_URL.replace("https://", "")
            assert result_default == f"https://user:mock_creds@{expected_host}"

            # Called for both invocations
            assert mock_ic.call_count == 2

    @pytest.mark.parametrize(
        "input_url,expected",
        [
            ("https://simple.example.com/", "https://user:X@simple.example.com/"),
            (
                "http://pypi.example.com/simple/",
                "http://user:X@pypi.example.com/simple/",
            ),
            (
                "https://pypi.example.com:8080/simple/",
                "https://user:X@pypi.example.com:8080/simple/",
            ),
            (
                "https://pypi.example.com/custom/path/?param=value",
                "https://user:X@pypi.example.com/custom/path/?param=value",
            ),
            (
                "https://registry.example.com:443/v1/repositories/simple/?format=json&auth=basic",
                "https://user:X@registry.example.com:443/v1/repositories/simple/?format=json&auth=basic",
            ),
        ],
    )
    def test_build_index_url_preserves_components(self, input_url, expected):
        """
        It preserves scheme, host, port, path, and query while injecting credentials.
        """
        with patch("safety.tool.auth.index_credentials", return_value="X") as mock_ic:
            result = build_index_url(self.ctx, input_url, "pypi")
            assert result == expected
            mock_ic.assert_called_once_with(self.ctx)

    def test_build_index_url_with_existing_auth_is_prepended(self):
        """
        Current implementation prepends user:<b64>@ before existing auth if present in netloc.
        """
        with patch(
            "safety.tool.auth.index_credentials", return_value="safety_creds"
        ) as mock_ic:
            url_with_auth = "https://old_user:old_pass@pypi.example.com/simple/"
            result = build_index_url(self.ctx, url_with_auth, "pypi")
            assert (
                result
                == "https://user:safety_creds@old_user:old_pass@pypi.example.com/simple/"
            )
            mock_ic.assert_called_once_with(self.ctx)
