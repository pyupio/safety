import logging
from abc import ABCMeta, abstractmethod

NOT_IMPLEMENTED = "You should implement this."

LOG = logging.getLogger(__name__)


class FormatterAPI:
    """
    Strategy Abstract class, with all the render methods that the concrete implementations should support
    """

    __metaclass__ = ABCMeta

    def __init__(self, **kwargs):
        """
        Dummy
        """
        pass

    @abstractmethod
    def render_vulnerabilities(self, announcements, vulnerabilities, remediations, full, packages, fixes=()):
        raise NotImplementedError(NOT_IMPLEMENTED)  # pragma: no cover

    @abstractmethod
    def render_licenses(self, announcements, licenses):
        raise NotImplementedError(NOT_IMPLEMENTED)  # pragma: no cover

    @abstractmethod
    def render_announcements(self, announcements):
        raise NotImplementedError(NOT_IMPLEMENTED)  # pragma: no cover


class SafetyFormatter(FormatterAPI):

    def render_vulnerabilities(self, announcements, vulnerabilities, remediations, full, packages, fixes=()):
        LOG.info('Safety is going to render_vulnerabilities with format: %s', self.format)
        return self.format.render_vulnerabilities(announcements, vulnerabilities, remediations, full, packages, fixes)

    def render_licenses(self, announcements, licenses):
        LOG.info('Safety is going to render_licenses with format: %s', self.format)
        return self.format.render_licenses(announcements, licenses)

    def render_announcements(self, announcements):
        LOG.info('Safety is going to render_announcements with format: %s', self.format)
        return self.format.render_announcements(announcements)

    def __init__(self, output, **kwargs):
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
