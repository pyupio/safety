"""
Test suite for TyposquattingProtection functionality.
"""

import pytest
from unittest.mock import MagicMock, patch

from safety.tool.typosquatting import TyposquattingProtection
from safety.tool.intents import CommandToolIntention, ToolIntentionType


@pytest.mark.unit
class TestTyposquattingProtection:
    """Test typosquatting protection functionality"""

    def setup_method(self):
        """Set up test fixtures"""
        # Use a small set of popular packages for testing
        self.popular_packages = [
            "requests",
            "flask",
            "django",
            "numpy",
            "pandas",
            "scipy",
            "matplotlib",
            "tensorflow",
            "pytorch",
            "boto3",
        ]
        self.protection = TyposquattingProtection(self.popular_packages)

    def test_check_package_exact_match_returns_valid(self):
        """Test that exact matches for popular packages return valid"""
        is_valid, suggestion = self.protection.check_package("requests")

        assert is_valid is True
        assert suggestion == "requests"

    def test_check_package_typo_returns_invalid_with_suggestion(self):
        """Test that typos return invalid with correct suggestion"""
        is_valid, suggestion = self.protection.check_package("reqests")  # missing 'u'

        assert is_valid is False
        assert suggestion == "requests"

    def test_check_package_similar_name_suggests_popular(self):
        """Test that similar names suggest popular packages"""
        is_valid, suggestion = self.protection.check_package("flaskk")  # extra 'k'

        assert is_valid is False
        assert suggestion == "flask"

    def test_check_package_edit_distance_threshold(self):
        """Test edit distance threshold based on package name length"""
        # Short names (<=5 chars) have threshold of 1
        is_valid, suggestion = self.protection.check_package(
            "flak"
        )  # edit distance 1 from "flask"
        assert is_valid is False
        assert suggestion == "flask"

        # Longer names have threshold of 2
        is_valid, suggestion = self.protection.check_package(
            "requets"
        )  # edit distance 2 from "requests"
        assert is_valid is False
        assert suggestion == "requests"

    def test_check_package_unknown_package_returns_valid(self):
        """Test that unknown packages (not typos) return valid"""
        is_valid, suggestion = self.protection.check_package(
            "completely-unknown-package"
        )

        assert is_valid is True
        assert suggestion == "completely-unknown-package"

    def test_check_package_length_difference_too_large(self):
        """Test that packages with large length differences are not flagged"""
        is_valid, suggestion = self.protection.check_package(
            "req"
        )  # too short compared to "requests"

        assert is_valid is True
        assert suggestion == "req"

    def test_coerce_add_intention_prompts_with_install(self):
        """Test ADD intention prompts with 'install' verb"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.ADD_PACKAGE

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            mock_prompt.return_value = "y"

            result = self.protection.coerce(intention, "reqests")  # typo

            # Should ask about installing and return corrected name
            mock_prompt.assert_called_once()
            call_args = mock_prompt.call_args
            assert "install reqests" in call_args[1]["prompt"]
            assert "install requests" in call_args[1]["prompt"]
            assert result == "requests"

    def test_coerce_download_intention_prompts_with_download(self):
        """Test DOWNLOAD intention prompts with 'download' verb"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.DOWNLOAD_PACKAGE

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            mock_prompt.return_value = "y"

            result = self.protection.coerce(intention, "flsk")  # typo for flask

            # Should ask about downloading
            mock_prompt.assert_called_once()
            call_args = mock_prompt.call_args
            assert "download flsk" in call_args[1]["prompt"]
            assert "download flask" in call_args[1]["prompt"]
            assert result == "flask"

    def test_coerce_build_intention_prompts_with_build(self):
        """Test BUILD intention prompts with 'build' verb"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.BUILD_PROJECT

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            mock_prompt.return_value = "y"

            result = self.protection.coerce(intention, "djnago")  # typo for django

            # Should ask about building
            mock_prompt.assert_called_once()
            call_args = mock_prompt.call_args
            assert "build djnago" in call_args[1]["prompt"]
            assert "build django" in call_args[1]["prompt"]
            assert result == "django"

    def test_coerce_user_says_no_returns_original(self):
        """Test that user saying 'no' returns original package name"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.ADD_PACKAGE

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            mock_prompt.return_value = "n"

            result = self.protection.coerce(intention, "reqests")

            # Should return original typo since user said no
            assert result == "reqests"

    def test_coerce_valid_package_no_prompt(self):
        """Test that valid packages don't trigger prompts"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.ADD_PACKAGE

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            result = self.protection.coerce(intention, "requests")

            # Should not prompt for valid packages
            mock_prompt.assert_not_called()
            assert result == "requests"

    def test_coerce_unknown_package_no_prompt(self):
        """Test that unknown packages don't trigger prompts"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.ADD_PACKAGE

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            result = self.protection.coerce(intention, "my-custom-package")

            # Should not prompt for unknown packages
            mock_prompt.assert_not_called()
            assert result == "my-custom-package"

    def test_coerce_prompt_defaults_to_yes(self):
        """Test that the prompt defaults to 'yes'"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.ADD_PACKAGE

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            mock_prompt.return_value = "y"

            self.protection.coerce(intention, "reqests")

            # Check that prompt was called with correct defaults
            call_args = mock_prompt.call_args
            assert call_args[1]["default"] == "y"
            assert call_args[1]["show_default"] is True
            assert call_args[1]["choices"] == ["y", "n"]

    def test_coerce_case_insensitive_response(self):
        """Test that user response is case insensitive"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.ADD_PACKAGE

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            # Test uppercase Y
            mock_prompt.return_value = "Y"
            result = self.protection.coerce(intention, "reqests")
            assert result == "requests"  # Should correct the typo

            # Test uppercase N
            mock_prompt.return_value = "N"
            result = self.protection.coerce(intention, "reqests")
            assert result == "reqests"  # Should keep original

    def test_multiple_similar_packages_suggests_closest(self):
        """Test that closest match is suggested when multiple similar packages exist"""
        # Add similar packages to test closest match selection
        packages_with_similar = self.popular_packages + ["request", "requests-oauthlib"]
        protection = TyposquattingProtection(packages_with_similar)

        # "reqests" is closest to "requests" (1 edit) vs "request" (2 edits)
        is_valid, suggestion = protection.check_package("reqests")

        assert is_valid is False
        assert suggestion == "requests"

    def test_nltk_edit_distance_calculation(self):
        """Test that NLTK edit distance is used correctly"""
        # Test known edit distances
        with patch(
            "safety.tool.typosquatting.nltk.edit_distance"
        ) as mock_edit_distance:
            mock_edit_distance.return_value = 1

            is_valid, suggestion = self.protection.check_package("reqests")

            # Should have called nltk.edit_distance
            mock_edit_distance.assert_called()
            assert is_valid is False

    @pytest.mark.parametrize(
        "package_name,expected_valid,expected_suggestion",
        [
            ("requests", True, "requests"),  # Exact match
            ("reqests", False, "requests"),  # Missing 'u'
            ("flask", True, "flask"),  # Exact match
            ("flsk", False, "flask"),  # Missing 'a'
            ("django", True, "django"),  # Exact match
            ("djnago", False, "django"),  # Swapped 'a' and 'n'
            (
                "completely-new-package",
                True,
                "completely-new-package",
            ),  # Unknown package
        ],
    )
    def test_check_package_various_cases(
        self, package_name, expected_valid, expected_suggestion
    ):
        """Test various package name checking scenarios"""
        is_valid, suggestion = self.protection.check_package(package_name)

        assert is_valid == expected_valid
        assert suggestion == expected_suggestion

    def test_console_parameter_passed_to_prompt(self):
        """Test that console parameter is passed to Rich Prompt"""
        intention = MagicMock(spec=CommandToolIntention)
        intention.intention_type = ToolIntentionType.ADD_PACKAGE

        with patch("safety.tool.typosquatting.Prompt.ask") as mock_prompt:
            mock_prompt.return_value = "y"

            self.protection.coerce(intention, "reqests")

            # Check that console parameter was passed
            call_args = mock_prompt.call_args
            assert "console" in call_args[1]
