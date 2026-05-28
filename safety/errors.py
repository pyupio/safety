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
        message: str = "Unhandled exception happened: {info}\n"
        "Re-run with '--debug' to see the full error details, "
        "and report this issue at https://github.com/pyupio/safety/issues",
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
        message: str = "An unexpected Safety CLI error occurred. "
        "Try running with '--debug' for more details, or check the documentation at https://docs.safetycli.com",
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
        message: str = "Safety CLI cannot read the data fetched from {fetched_from} because it is malformed.\n"
        "This may be caused by a corrupted download. Try re-running the command. "
        "If the problem persists, contact Safety CLI support.\n",
    ):
        info = f"Reason, {reason}" if reason else ""
        info = "Reason, {reason}".format(reason=reason)
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
        self,
        message: str = "Unable to load the vulnerability database. "
        "Check your network connection and ensure the database source is reachable. "
        "If you are using a local database, verify the path is correct with '--db'.",
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
        self, message: str = "Unable to parse the requirement: {line}", line: str = ""
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
        message: str = "Unable to find vulnerability database in {db}. "
        "Specify the correct path using the '--db' option or ensure the database file exists at the expected location.",
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
        message: str = "Your authentication credential{credential}is invalid. See {link}.",
        reason: Optional[str] = None,
    ):
        self.credential = credential
        self.link = (
            "https://docs.safetycli.com/safety-docs/support/invalid-api-key-error"
        )
        self.message = (
            message.format(credential=f" '{self.credential}' ", link=self.link)
            if self.credential
            else message.format(credential=" ", link=self.link)
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
        message: str = "Email is not verified. "
        "Please check your inbox for the verification email and verify your account before proceeding. "
        "You can request a new verification email from your Safety Platform profile.",
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
        message: str = "Too many requests. "
        "You have exceeded the rate limit for API requests. "
        "Please wait before retrying, or reduce the frequency of your requests.",
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
        message: str = "Unable to reach the Safety server. Check your network connection, "
        "firewall settings, and proxy configuration. If you use a proxy, configure it "
        "with 'safety configure' or set the appropriate environment variables.",
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
        message: str = "SSL certificate verification failed. "
        "This can happen if your system's root certificates are outdated or if a proxy is intercepting traffic. "
        "Try updating your system's CA certificates or ensure your proxy is configured correctly with 'safety configure'. "
        "See https://docs.safetycli.com/safety-docs/support/ssl-certificate-errors for more information.",
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
        message: str = "The request timed out. Check your network connection and try again. "
        "You can increase the timeout by setting the SAFETY_REQUEST_TIMEOUT environment variable. "
        "If you use a proxy, verify it is reachable and configured correctly.",
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
        message: str = "Safety server encountered an error. "
        "Our engineers have been notified. Please try again later. "
        "If the issue persists, check https://status.safetycli.com for service status.",
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
        "Ensure your enrollment key is correct and the Safety Platform is accessible. "
        "Run 'safety auth enroll <your-enrollment-key>' to try again.",
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
        message: str = "Machine enrollment failed due to a temporary issue. "
        "The Safety Platform may be temporarily unavailable. "
        "Please retry enrollment in a few minutes. "
        "If the problem persists, check your network connection and enrollment key.",
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
        message: str = "Unable to determine the system identity. "
        "This may be due to insufficient permissions or missing system identifiers. "
        "Ensure Safety CLI has the necessary permissions to read system information.",
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
