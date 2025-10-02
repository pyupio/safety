from typing import Optional

from safety.constants import (
    EXIT_CODE_EMAIL_NOT_VERIFIED,
    EXIT_CODE_FAILURE,
    EXIT_CODE_INVALID_AUTH_CREDENTIAL,
    EXIT_CODE_INVALID_PROVIDED_REPORT,
    EXIT_CODE_INVALID_REQUIREMENT,
    EXIT_CODE_MALFORMED_DB,
    EXIT_CODE_TOO_MANY_REQUESTS,
    EXIT_CODE_UNABLE_TO_FETCH_VULNERABILITY_DB,
    EXIT_CODE_UNABLE_TO_LOAD_LOCAL_VULNERABILITY_DB,
)


class SafetyException(Exception):
    """
    Base exception for Safety CLI errors.

    Args:
        message (str): The error message template.
        info (str): Additional information to include in the error message.
    """
    def __init__(self, message: str = "An unexpected error occurred in Safety CLI: {info}\n"
                                      "If this issue persists, please report it at: https://github.com/pyupio/safety/issues",
                 info: str = ""):
        self.message = message.format(info=info)
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this exception.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_FAILURE


class SafetyError(Exception):
    """
    Generic Safety CLI error.

    Args:
        message (str): The error message.
        error_code (Optional[int]): The error code.
    """
    def __init__(self, message: str = "An error occurred while running Safety CLI.\n"
                                      "Please check your configuration and try again.",
                 error_code: Optional[int] = None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_FAILURE


class MalformedDatabase(SafetyError):
    """
    Error raised when the vulnerability database is malformed.

    Args:
        reason (Optional[str]): The reason for the error.
        fetched_from (str): The source of the fetched data.
        message (str): The error message template.
    """
    def __init__(self, reason: Optional[str] = None, fetched_from: str = "server",
                 message: str = "Unable to read vulnerability database from {fetched_from}.\n"
                                "The data appears to be malformed or corrupted.\n"):
        info = f"Details: {reason}\n" if reason else ""
        suggestion = "Try running the command again. If the issue persists, please report it at: https://github.com/pyupio/safety/issues"
        self.message = message.format(fetched_from=fetched_from) + info + suggestion
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_MALFORMED_DB


class DatabaseFetchError(SafetyError):
    """
    Error raised when the vulnerability database cannot be fetched.

    Args:
        message (str): The error message.
    """
    def __init__(self, message: str = "Unable to load vulnerability database.\n"
                                      "Please check your internet connection and try again."):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_UNABLE_TO_FETCH_VULNERABILITY_DB


class InvalidProvidedReportError(SafetyError):
    """
    Error raised when the provided report is invalid for applying fixes.

    Args:
        message (str): The error message.
    """
    def __init__(self, message: str = "Unable to apply fix: the report must be generated from a file.\n"
                                      "Environment-based reports are not yet supported.\n"
                                      "Please generate a report from a requirements file and try again."):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_INVALID_PROVIDED_REPORT


class InvalidRequirementError(SafetyError):
    """
    Error raised when a requirement is invalid.

    Args:
        message (str): The error message template.
        line (str): The invalid requirement line.
    """
    def __init__(self, message: str = "Unable to parse requirement: {line}\n"
                                      "Please check the syntax and ensure it follows Python package specification format.\n"
                                      "For help, see: https://pip.pypa.io/en/stable/reference/requirements-file-format/",
                 line: str = ""):
        self.message = message.format(line=line)
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_INVALID_REQUIREMENT


class DatabaseFileNotFoundError(DatabaseFetchError):
    """
    Error raised when the vulnerability database file is not found.

    Args:
        db (Optional[str]): The database file path.
        message (str): The error message template.
    """
    def __init__(self, db: Optional[str] = None,
                 message: str = "Vulnerability database file not found: {db}\n"
                                "Please verify the file path exists and you have read permissions."):
        self.db = db
        self.message = message.format(db=db)
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_UNABLE_TO_LOAD_LOCAL_VULNERABILITY_DB


class InvalidCredentialError(DatabaseFetchError):
    """
    Error raised when authentication credentials are invalid.

    Args:
        credential (Optional[str]): The invalid credential.
        message (str): The error message template.
        reason (Optional[str]): The reason for the error.
    """

    def __init__(self, credential: Optional[str] = None,
                 message: str = "Authentication failed: Your credential{credential}is invalid or has expired.\n"
                                "Please verify your API key and try again.\n"
                                "For help, visit: {link}",
                 reason: Optional[str] = None):
        self.credential = credential
        self.link = 'https://docs.safetycli.com/safety-docs/support/invalid-api-key-error'
        credential_text = f" '{self.credential}' " if self.credential else " "
        self.message = message.format(credential=credential_text, link=self.link)
        if reason:
            self.message += f"\nDetails: {reason}"
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_INVALID_AUTH_CREDENTIAL

class NotVerifiedEmailError(SafetyError):
    """
    Error raised when the user's email is not verified.

    Args:
        message (str): The error message.
    """
    def __init__(self, message: str = "Email verification required.\n"
                                      "Please check your inbox and verify your email address to continue.\n"
                                      "If you haven't received the verification email, check your spam folder or request a new one."):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_EMAIL_NOT_VERIFIED

class TooManyRequestsError(DatabaseFetchError):
    """
    Error raised when too many requests are made to the server.

    Args:
        reason (Optional[str]): The reason for the error.
        message (str): The error message template.
    """
    def __init__(self, reason: Optional[str] = None,
                 message: str = "Rate limit exceeded: Too many requests sent to the server.\n"
                                "Please wait a few moments before trying again."):
        self.message = message
        if reason:
            self.message += f"\nDetails: {reason}"
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_TOO_MANY_REQUESTS


class NetworkConnectionError(DatabaseFetchError):
    """
    Error raised when there is a network connection issue.

    Args:
        message (str): The error message.
    """

    def __init__(self, message: str = "Network connection error: Unable to reach the server.\n"
                                      "Please check your internet connection and try again.\n"
                                      "If you're behind a proxy or firewall, ensure Safety CLI is allowed to connect."):
        self.message = message
        super().__init__(self.message)


class RequestTimeoutError(DatabaseFetchError):
    """
    Error raised when a request times out.

    Args:
        message (str): The error message.
    """
    def __init__(self, message: str = "Request timed out: The server did not respond in time.\n"
                                      "This may be due to network congestion or slow internet connection.\n"
                                      "Please try again. If the problem persists, check your network settings."):
        self.message = message
        super().__init__(self.message)


class ServerError(DatabaseFetchError):
    """
    Error raised when there is a server issue.

    Args:
        reason (Optional[str]): The reason for the error.
        message (str): The error message template.
    """
    def __init__(self, reason: Optional[str] = None,
                 message: str = "Server error: Something went wrong on our end.\n"
                                "Our engineering team has been notified and is working to resolve the issue.\n"
                                "Please try again in a few minutes."):
        self.message = message
        if reason:
            self.message += f"\nDetails: {reason}"
        super().__init__(self.message)
