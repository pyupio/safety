# type: ignore
import unittest
import json
import base64
from unittest.mock import MagicMock

import typer
from safety.tool.auth import index_credentials


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
