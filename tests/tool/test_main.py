"""
Unit tests for safety.tool.main.configure_system() tools filtering.
"""

from unittest.mock import patch

import pytest

from safety.tool.main import configure_system


class TestConfigureSystemToolsFilter:
    """
    Tests for the tools parameter of configure_system().
    """

    @pytest.mark.unit
    def test_no_filter_configures_all_tools(self) -> None:
        """
        When tools=None, all four configurators are called.
        """
        with (
            patch("safety.tool.main.PipConfigurator") as pip_cls,
            patch("safety.tool.main.PoetryConfigurator") as poetry_cls,
            patch("safety.tool.main.UvConfigurator") as uv_cls,
            patch("safety.tool.main.NpmConfigurator") as npm_cls,
        ):
            for cls in (pip_cls, poetry_cls, uv_cls, npm_cls):
                cls.return_value.configure.return_value = None

            results = configure_system(org_slug="test-org", tools=None)

            assert len(results) == 4
            pip_cls.return_value.configure.assert_called_once_with(org_slug="test-org")
            poetry_cls.return_value.configure.assert_called_once_with(
                org_slug="test-org"
            )
            uv_cls.return_value.configure.assert_called_once_with(org_slug="test-org")
            npm_cls.return_value.configure.assert_called_once_with(org_slug="test-org")

    @pytest.mark.unit
    def test_filter_configures_only_selected_tools(self) -> None:
        """
        When tools=["pip", "uv"], only pip and uv configurators are called.
        """
        with (
            patch("safety.tool.main.PipConfigurator") as pip_cls,
            patch("safety.tool.main.PoetryConfigurator") as poetry_cls,
            patch("safety.tool.main.UvConfigurator") as uv_cls,
            patch("safety.tool.main.NpmConfigurator") as npm_cls,
        ):
            for cls in (pip_cls, poetry_cls, uv_cls, npm_cls):
                cls.return_value.configure.return_value = None

            results = configure_system(org_slug="test-org", tools=["pip", "uv"])

            assert len(results) == 2
            pip_cls.return_value.configure.assert_called_once()
            uv_cls.return_value.configure.assert_called_once()
            poetry_cls.return_value.configure.assert_not_called()
            npm_cls.return_value.configure.assert_not_called()

    @pytest.mark.unit
    def test_filter_single_tool(self) -> None:
        """
        When tools=["npm"], only npm configurator is called.
        """
        with (
            patch("safety.tool.main.PipConfigurator") as pip_cls,
            patch("safety.tool.main.PoetryConfigurator") as poetry_cls,
            patch("safety.tool.main.UvConfigurator") as uv_cls,
            patch("safety.tool.main.NpmConfigurator") as npm_cls,
        ):
            for cls in (pip_cls, poetry_cls, uv_cls, npm_cls):
                cls.return_value.configure.return_value = None

            results = configure_system(org_slug="test-org", tools=["npm"])

            assert len(results) == 1
            npm_cls.return_value.configure.assert_called_once()
            pip_cls.return_value.configure.assert_not_called()
            poetry_cls.return_value.configure.assert_not_called()
            uv_cls.return_value.configure.assert_not_called()

    @pytest.mark.unit
    def test_empty_tools_list_configures_all(self) -> None:
        """
        When tools=[] (empty list is falsy), all configurators are called
        — same behavior as tools=None.
        """
        with (
            patch("safety.tool.main.PipConfigurator") as pip_cls,
            patch("safety.tool.main.PoetryConfigurator") as poetry_cls,
            patch("safety.tool.main.UvConfigurator") as uv_cls,
            patch("safety.tool.main.NpmConfigurator") as npm_cls,
        ):
            for cls in (pip_cls, poetry_cls, uv_cls, npm_cls):
                cls.return_value.configure.return_value = None

            results = configure_system(org_slug="test-org", tools=[])

            assert len(results) == 4
