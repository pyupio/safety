from pathlib import Path
import unittest
from unittest.mock import Mock, call, patch

from safety.init.main import (
    PROJECT_CONFIG_ID,
    PROJECT_CONFIG_NAME,
    PROJECT_CONFIG_URL,
    PROJECT_CONFIG_SECTION,
    check_project,
    create_project,
    save_project_info,
    save_verified_project,
)

from safety_schemas.models import ProjectModel, Stage


class TestInitMain(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    @patch("safety.init.main.prompt_project_id")
    @patch("safety.init.main.print_wait_project_verification")
    def test_check_project_without_id(self, mock_wait_verification, mock_prompt_id):
        """
        If not project id is provided, the user should be prompted for one,
        then the project should be verified.
        """
        ctx = Mock()
        ctx.obj.auth.stage = Stage.production
        ctx.obj.telemetry = Mock(safety_source="cli")

        session = Mock()
        console = Mock()
        unverified_project = Mock(
            id=None, project_path=Path("/test/dir/project/.safety-project.ini")
        )

        # Mock prompt returning project id
        mock_prompt_id.return_value = "prompted-id"
        mock_wait_verification.return_value = {"status": "success"}

        _ = check_project(ctx, session, console, unverified_project, git_origin=None)

        # Assert prompt was called with parent dir name
        mock_prompt_id.assert_called_once_with(console, "project")

        # Assert core data is correct with prompted id
        expected_data = {
            "scan_stage": Stage.production,
            "safety_source": "cli",
            "project_slug": "prompted-id",
            "project_slug_source": "user",
        }

        # Assert verification called with prompted data
        mock_wait_verification.assert_called_once_with(
            console,
            "prompted-id",
            (session.check_project, expected_data),
            on_error_delay=1,
        )

    @patch("safety.init.main.save_project_info")
    def test_save_verified_project(self, mock_save_project_info):
        ctx = Mock()
        ctx.obj = Mock()

        project = {
            "id": "test-project",
            "name": "Test Project",
            "project_path": Path("/path/to/project"),
            "url_path": "/test/url",
        }

        organization = {"name": "Test Organization", "slug": "test-org"}

        save_verified_project(
            ctx,
            slug=project["id"],
            **{
                k: v
                for k, v in {**project, **{"organization": organization}}.items()
                if k != "id"
            },
        )

        # Assert project is correct type and values
        self.assertIsInstance(ctx.obj.project, ProjectModel)
        for attr, expected in project.items():
            self.assertEqual(getattr(ctx.obj.project, attr), expected)

        self.assertEqual(ctx.obj.org.get("name"), organization.get("name"))
        self.assertEqual(ctx.obj.org.get("slug"), organization.get("slug"))

        mock_save_project_info.assert_called_once_with(
            project=ctx.obj.project, project_path=project["project_path"]
        )

    @patch("configparser.ConfigParser")
    def test_save_project_info_success(self, mock_config_cls):
        # case_name, project, expected_config
        test_cases = [
            (
                "full_project",
                ProjectModel(
                    id="test-id", url_path="http://example.com", name="Test Project"
                ),
                {
                    PROJECT_CONFIG_ID: "test-id",
                    PROJECT_CONFIG_URL: "http://example.com",
                    PROJECT_CONFIG_NAME: "Test Project",
                },
            ),
            ("id_only", ProjectModel(id="test-id"), {PROJECT_CONFIG_ID: "test-id"}),
            (
                "with_url",
                ProjectModel(id="test-id", url_path="http://example.com"),
                {
                    PROJECT_CONFIG_ID: "test-id",
                    PROJECT_CONFIG_URL: "http://example.com",
                },
            ),
            (
                "with_name",
                ProjectModel(id="test-id", name="Test Project"),
                {PROJECT_CONFIG_ID: "test-id", PROJECT_CONFIG_NAME: "Test Project"},
            ),
        ]

        mock_config = mock_config_cls.return_value
        section_mock = mock_config.__getitem__.return_value

        for case_name, project, expected_config in test_cases:
            with self.subTest(case_name=case_name):
                mock_config.reset_mock()

                result = save_project_info(project, "test_config.ini")  # type: ignore

                # Assert the result
                self.assertTrue(result)
                mock_config.__getitem__.assert_called_with(PROJECT_CONFIG_SECTION)

                calls = [call(key, value) for key, value in expected_config.items()]
                section_mock.__setitem__.assert_has_calls(calls, any_order=False)

    @patch("configparser.ConfigParser")
    def test_save_project_info_file_error(self, mock_config_cls):
        project = ProjectModel(id="test-id")

        mock_config = mock_config_cls.return_value
        mock_config.write.side_effect = Exception("Write error")

        result = save_project_info(project, "test_config.ini")  # type: ignore

        self.assertFalse(result)

    @patch("safety.init.main.load_unverified_project_from_config")
    @patch("safety.init.main.GIT")
    @patch("safety.init.main.verify_project")
    def test_create_project_with_platform_enabled(
        self, mock_verify, mock_git, mock_load_project
    ):
        ctx = Mock()
        ctx.obj.platform_enabled = True
        console = Mock()
        target = Path("/some/path")

        mock_git_instance = mock_git.return_value
        mock_git_instance.build_git_data.return_value = Mock(origin="test-origin")
        mock_project = mock_load_project.return_value

        create_project(ctx, console, target)

        # Make sure project loads unverified, git data is built and
        # project verification is called
        mock_load_project.assert_called_once_with(project_root=target)
        mock_git_instance.build_git_data.assert_called_once()
        mock_verify.assert_called_once_with(
            console,
            ctx,
            ctx.obj.auth.client,
            mock_project,
            ctx.obj.auth.stage,
            "test-origin",
        )

    @patch("safety.init.main.load_unverified_project_from_config")
    @patch("safety.init.main.GIT")
    @patch("safety.init.main.verify_project")
    def test_create_project_platform_disabled(
        self, mock_verify, mock_git, mock_load_project
    ):
        ctx = Mock()
        ctx.obj.platform_enabled = False
        console = Mock()
        target = Path("/some/path")

        create_project(ctx, console, target)

        mock_verify.assert_not_called()
        console.print.assert_called_once_with(
            "Project creation is not supported for your account."
        )
