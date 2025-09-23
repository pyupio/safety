"""
Typosquatting detection for various tools.
"""

import logging
import nltk
from typing import Tuple, List

from safety.console import main_console as console
from rich.prompt import Prompt
from .intents import CommandToolIntention, ToolIntentionType

logger = logging.getLogger(__name__)


class TyposquattingProtection:
    """
    Base class for typosquatting detection.
    """

    def __init__(self, popular_packages: List[str]):
        self.popular_packages = popular_packages

    def check_package(self, package_name: str) -> Tuple[bool, str]:
        """
        Check if a package name is likely to be a typosquatting attempt.

        Args:
            package_name: Name of the package to check

        Returns:
            Tuple of (is_valid, suggested_package_name)
        """
        max_edit_distance = 2 if len(package_name) > 5 else 1

        if package_name in self.popular_packages:
            return (True, package_name)

        for pkg in self.popular_packages:
            if (
                abs(len(pkg) - len(package_name)) <= max_edit_distance
                and nltk.edit_distance(pkg, package_name) <= max_edit_distance
            ):
                return (False, pkg)

        return (True, package_name)

    def coerce(self, intention: CommandToolIntention, dependency_name: str) -> str:
        """
        Coerce a package name to its correct name if it is a typosquatting attempt.

        Args:
            intention: CommandToolIntention object
            dependency_name: Name of the package to coerce

        Returns:
            str: Coerced package name
        """
        (valid, candidate_package_name) = self.check_package(dependency_name)

        if not valid:
            action = "install"

            if intention.intention_type == ToolIntentionType.DOWNLOAD_PACKAGE:
                action = "download"
            elif intention.intention_type == ToolIntentionType.BUILD_PROJECT:
                action = "build"
            elif intention.intention_type == ToolIntentionType.SEARCH_PACKAGES:
                action = "search"

            prompt = f"You are about to {action} {dependency_name} package. Did you mean to {action} {candidate_package_name}?"
            answer = Prompt.ask(
                prompt=prompt,
                choices=["y", "n"],
                default="y",
                show_default=True,
                console=console,
            ).lower()
            if answer == "y":
                return candidate_package_name

        return dependency_name
