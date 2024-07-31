import logging
from abc import ABCMeta, abstractmethod
from typing import Any, Dict, List, Tuple, Union, Optional

NOT_IMPLEMENTED = "You should implement this."

LOG = logging.getLogger(__name__)


class FormatterAPI:
    """
    Strategy Abstract class, with all the render methods that the concrete implementations should support.
    """

    __metaclass__ = ABCMeta

    def __init__(self, **kwargs: Any) -> None:
        """
        Dummy initializer for the FormatterAPI class.
        """
        pass

    @abstractmethod
    def render_vulnerabilities(self, announcements: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]], remediations: Dict[str, Any], full: bool, packages: List[Dict[str, Any]], fixes: Tuple = ()) -> Optional[str]:
        """
        Render the vulnerabilities report.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.
            vulnerabilities (List[Dict[str, Any]]): List of vulnerabilities.
            remediations (Dict[str, Any]): Dictionary of remediations.
            full (bool): Whether to render a full report.
            packages (List[Dict[str, Any]]): List of packages.
            fixes (Tuple, optional): Tuple of fixes. Defaults to ().

        Returns:
            Optional[str]: Rendered vulnerabilities report.
        """
        raise NotImplementedError(NOT_IMPLEMENTED)  # pragma: no cover

    @abstractmethod
    def render_licenses(self, announcements: List[Dict[str, Any]], licenses: List[Dict[str, Any]]) -> Optional[str]:
        """
        Render the licenses report.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.
            licenses (List[Dict[str, Any]]): List of licenses.

        Returns:
            Optional[str]: Rendered licenses report.
        """
        raise NotImplementedError(NOT_IMPLEMENTED)  # pragma: no cover

    @abstractmethod
    def render_announcements(self, announcements: List[Dict[str, Any]]) -> Optional[str]:
        """
        Render the announcements.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.

        Returns:
            Optional[str]: Rendered announcements.
        """
        raise NotImplementedError(NOT_IMPLEMENTED)  # pragma: no cover


class SafetyFormatter(FormatterAPI):
    """
    Formatter class that implements the FormatterAPI to render reports in various formats.
    """
    def __init__(self, output: str, **kwargs: Any) -> None:
        """
        Initialize the SafetyFormatter with the specified output format.

        Args:
            output (str): The output format (e.g., 'json', 'html', 'bare', 'text').
            **kwargs: Additional keyword arguments.
        """
        from safety.formatters.screen import ScreenReport
        from safety.formatters.text import TextReport
        from safety.formatters.json import JsonReport
        from safety.formatters.bare import BareReport
        from safety.formatters.html import HTMLReport

        self.format = ScreenReport(**kwargs)

        if output == 'json':
            self.format = JsonReport(**kwargs)
        elif output == 'html':
            self.format = HTMLReport(**kwargs)
        elif output == 'bare':
            self.format = BareReport(**kwargs)
        elif output == 'text':
            self.format = TextReport(**kwargs)

    def render_vulnerabilities(self, announcements: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]], remediations: Dict[str, Any], full: bool, packages: List[Dict[str, Any]], fixes: Tuple = ()) -> Optional[str]:
        """
        Render the vulnerabilities report.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.
            vulnerabilities (List[Dict[str, Any]]): List of vulnerabilities.
            remediations (Dict[str, Any]): Dictionary of remediations.
            full (bool): Whether to render a full report.
            packages (List[Dict[str, Any]]): List of packages.
            fixes (Tuple, optional): Tuple of fixes. Defaults to ().

        Returns:
            Optional[str]: Rendered vulnerabilities report.
        """
        LOG.info('Safety is going to render_vulnerabilities with format: %s', self.format)
        return self.format.render_vulnerabilities(announcements, vulnerabilities, remediations, full, packages, fixes)

    def render_licenses(self, announcements: List[Dict[str, Any]], licenses: List[Dict[str, Any]]) -> Optional[str]:
        """
        Render the licenses report.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.
            licenses (List[Dict[str, Any]]): List of licenses.

        Returns:
            Optional[str]: Rendered licenses report.
        """
        LOG.info('Safety is going to render_licenses with format: %s', self.format)
        return self.format.render_licenses(announcements, licenses)

    def render_announcements(self, announcements: List[Dict[str, Any]]):
        """
        Render the announcements.

        Args:
            announcements (List[Dict[str, Any]]): List of announcements.

        Returns:
            Optional[str]: Rendered announcements.
        """
        LOG.info('Safety is going to render_announcements with format: %s', self.format)
        return self.format.render_announcements(announcements)
