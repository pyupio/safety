"""
Typosquatting detection for various tools.
"""

import logging
import nltk
from typing import Tuple, List

from safety.console import main_console as console
from rich.prompt import Prompt

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

    def coerce(self, dependency_name: str) -> str:
        """
        Coerce a package name to its correct name if it is a typosquatting attempt.

        Args:
            dependency_name: Name of the package to coerce

        Returns:
            str: Coerced package name
        """
        (valid, candidate_package_name) = self.check_package(dependency_name)

        if not valid:
            prompt = f"You are about to install {dependency_name} package. Did you mean to install {candidate_package_name}?"
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
