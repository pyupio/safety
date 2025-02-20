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
    def __init__(self, message: str = "Unhandled exception happened: {info}", info: str = ""):
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
    def __init__(self, message: str = "Unhandled Safety generic error", error_code: Optional[int] = None):
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
                 message: str = "Sorry, something went wrong.\n"
                                "Safety CLI cannot read the data fetched from {fetched_from} because it is malformed.\n"):
        info = f"Reason, {reason}" if reason else ""
        info = "Reason, {reason}".format(reason=reason)
        self.message = message.format(fetched_from=fetched_from) + (info if reason else "")
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
    def __init__(self, message: str = "Unable to load vulnerability database"):
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
    def __init__(self, message: str = "Unable to apply fix: the report needs to be generated from a file. "
                                      "Environment isn't supported yet."):
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
    def __init__(self, message: str = "Unable to parse the requirement: {line}", line: str = ""):
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
    def __init__(self, db: Optional[str] = None, message: str = "Unable to find vulnerability database in {db}"):
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
                 message: str = "Your authentication credential{credential}is invalid. See {link}.",
                 reason: Optional[str] = None):
        self.credential = credential
        self.link = 'https://docs.safetycli.com/safety-docs/support/invalid-api-key-error'
        self.message = message.format(credential=f" '{self.credential}' ", link=self.link) if self.credential else message.format(credential=' ', link=self.link)
        info = f" Reason: {reason}"
        self.message = self.message + (info if reason else "")
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
    def __init__(self, message: str = "email is not verified"):
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
                 message: str = "Too many requests."):
        info = f" Reason: {reason}"
        self.message = message + (info if reason else "")
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

    def __init__(self, message: str = "Check your network connection, unable to reach the server."):
        self.message = message
        super().__init__(self.message)


class RequestTimeoutError(DatabaseFetchError):
    """
    Error raised when a request times out.

    Args:
        message (str): The error message.
    """
    def __init__(self, message: str = "Check your network connection, the request timed out."):
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
                 message: str = "Sorry, something went wrong.\n"
                                "Our engineers are working quickly to resolve the issue."):
        info = f" Reason: {reason}"
        self.message = message + (info if reason else "")
        super().__init__(self.message)
