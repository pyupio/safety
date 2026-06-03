"""
Custom exception and error classes used by the Safety CLI.

Hierarchy:
    SafetyException (base, exit code 1)
    └── SafetyError (generic error base)
         ├── MalformedDatabase
         ├── DatabaseFetchError
         │    ├── InvalidCredentialError
         │    ├── TooManyRequestsError
         │    ├── RequestTimeoutError
         │    └── ServerError
         ├── DatabaseFileNotFoundError
         ├── InvalidProvidedReportError
         ├── InvalidRequirementError
         ├── NotVerifiedEmailError
         ├── NetworkConnectionError
         │    └── SSLCertificateError
         ├── EnrollmentError
         │    └── EnrollmentTransientFailure
         └── MachineIdUnavailableError

Each class defines a ``get_exit_code()`` method returning a dedicated
exit code from ``safety.constants`` so that callers can distinguish
error types in scripts and CI pipelines.
"""
from typing import Optional

from safety.constants import (
    EXIT_CODE_EMAIL_NOT_VERIFIED,
    EXIT_CODE_ENROLLMENT_FAILED,
    EXIT_CODE_ENROLLMENT_FAILED_RETRYABLE,
    EXIT_CODE_FAILURE,
    EXIT_CODE_INVALID_AUTH_CREDENTIAL,
    EXIT_CODE_INVALID_PROVIDED_REPORT,
    EXIT_CODE_INVALID_REQUIREMENT,
    EXIT_CODE_MACHINE_ID_UNAVAILABLE,
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

    def __init__(
        self,
        message: str = "An unexpected Safety CLI error occurred: {info}",
        info: str = "",
    ):
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

    def __init__(
        self,
        message: str = "An unexpected Safety CLI error occurred.",
        error_code: Optional[int] = None,
    ):
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

    def __init__(
        self,
        reason: Optional[str] = None,
        fetched_from: str = "server",
        message: str = "The vulnerability database fetched from {fetched_from} is malformed "
        "and cannot be read by Safety CLI.\n",
    ):
        info = f"Reason: {reason}" if reason else ""
        self.message = message.format(fetched_from=fetched_from) + (
            info if reason else ""
        )
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

    def __init__(
        self, message: str = "Unable to fetch the vulnerability database. "
        "Please check your network connection and try again."
    ):
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

    def __init__(
        self,
        message: str = "Unable to apply fix: the report needs to be generated from a file. "
        "Environment isn't supported yet.",
    ):
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

    def __init__(
        self,
        message: str = "Unable to parse the package requirement: '{line}'. "
        "Please ensure the requirement format is valid.",
        line: str = "",
    ):
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

    def __init__(
        self,
        db: Optional[str] = None,
        message: str = "Unable to find the vulnerability database file at: {db}. "
        "Please verify the file exists and the path is correct.",
    ):
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

    def __init__(
        self,
        credential: Optional[str] = None,
        message: str = "Your authentication credential is invalid. See {link}.",
        reason: Optional[str] = None,
    ):
        self.credential = credential
        self.link = (
            "https://docs.safetycli.com/safety-docs/support/invalid-api-key-error"
        )
        credential_info = f" Credential: '{credential}'" if credential else ""
        self.message = (
            message.format(link=self.link) + credential_info
        )
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

    def __init__(
        self,
        message: str = "Your Safety account email is not verified. "
        "Please check your inbox and verify your email address to continue.",
    ):
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

    def __init__(
        self,
        reason: Optional[str] = None,
        message: str = "Too many requests sent to the Safety server. "
        "Please wait and try again later.",
    ):
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


class NetworkConnectionError(SafetyError):
    """
    Error raised when there is a network connection issue.

    Args:
        message (str): The error message.
    """

    def __init__(
        self,
        message: str = "Unable to reach the Safety server. "
        "Please check your network connection and try again.",
    ):
        self.message = message
        super().__init__(self.message)


class SSLCertificateError(NetworkConnectionError):
    """
    Error raised when there is a SSL certificate issue.

    Args:
        message (str): The error message.
    """

    def __init__(
        self,
        message: str = "SSL certificate verification failed when connecting to the Safety server. "
        "This may be caused by a proxy, corporate firewall, or outdated root certificates. "
        "See https://docs.safetycli.com for TLS configuration options.",
    ):
        self.message = message
        super().__init__(self.message)


class RequestTimeoutError(DatabaseFetchError):
    """
    Error raised when a request times out.

    Args:
        message (str): The error message.
    """

    def __init__(
        self,
        message: str = "Request to the Safety server timed out. "
        "Please check your network connection and try again.",
    ):
        self.message = message
        super().__init__(self.message)


class ServerError(DatabaseFetchError):
    """
    Error raised when there is a server issue.

    Args:
        reason (Optional[str]): The reason for the error.
        message (str): The error message template.
    """

    def __init__(
        self,
        reason: Optional[str] = None,
        message: str = "The Safety server encountered an error. "
        "Our engineers are working to resolve the issue. Please try again later.",
    ):
        info = f" Reason: {reason}"
        self.message = message + (info if reason else "")
        super().__init__(self.message)


class EnrollmentError(SafetyError):
    """
    Error raised when machine enrollment fails.

    Args:
        message (str): The error message.
    """

    def __init__(
        self,
        message: str = "Machine enrollment failed. "
        "Please check your enrollment key and try again.",
    ):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_ENROLLMENT_FAILED


class EnrollmentTransientFailure(EnrollmentError):
    """
    Error raised when enrollment fails due to a transient/retryable condition.

    Covers 5xx server errors and network failures (after retry exhaustion).
    MDM orchestrators should retry enrollment when they see exit code 75.

    Args:
        message (str): The error message.
    """

    def __init__(
        self,
        message: str = "Machine enrollment failed due to a transient error. "
        "This is usually temporary. Please try again.",
    ):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_ENROLLMENT_FAILED_RETRYABLE


class MachineIdUnavailableError(SafetyError):
    """
    Error raised when the system machine identity cannot be determined.

    Args:
        message (str): The error message.
    """

    def __init__(
        self,
        message: str = "Unable to determine the unique identity of this machine. "
        "This is required for enrollment. "
        "Ensure the machine has a unique hostname and the required system files are accessible.",
    ):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self) -> int:
        """
        Get the exit code associated with this error.

        Returns:
            int: The exit code.
        """
        return EXIT_CODE_MACHINE_ID_UNAVAILABLE
