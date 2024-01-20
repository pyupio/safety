from typing import Optional
from safety.constants import EXIT_CODE_EMAIL_NOT_VERIFIED, EXIT_CODE_FAILURE, EXIT_CODE_INVALID_API_KEY, EXIT_CODE_TOO_MANY_REQUESTS, \
    EXIT_CODE_UNABLE_TO_FETCH_VULNERABILITY_DB, EXIT_CODE_UNABLE_TO_LOAD_LOCAL_VULNERABILITY_DB, EXIT_CODE_MALFORMED_DB, \
    EXIT_CODE_INVALID_PROVIDED_REPORT, EXIT_CODE_INVALID_REQUIREMENT


class SafetyException(Exception):

    def __init__(self, message="Unhandled exception happened: {info}", info=""):
        self.message = message.format(info=info)
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_FAILURE


class SafetyError(Exception):

    def __init__(self, message="Unhandled Safety generic error", error_code=None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_FAILURE


class MalformedDatabase(SafetyError):

    def __init__(self, reason=None, fetched_from="server",
                 message="Sorry, something went wrong.\n" +
                         "Safety CLI can not read the data fetched from {fetched_from} because is malformed.\n"):
        info = "Reason, {reason}".format(reason=reason)
        self.message = message.format(fetched_from=fetched_from) + (info if reason else "")
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_MALFORMED_DB


class DatabaseFetchError(SafetyError):

    def __init__(self, message="Unable to load vulnerability database"):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_UNABLE_TO_FETCH_VULNERABILITY_DB


class InvalidProvidedReportError(SafetyError):

    def __init__(self, message="Unable to apply fix: the report needs to be generated from a file. "
                               "Environment isn't supported yet."):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_INVALID_PROVIDED_REPORT


class InvalidRequirementError(SafetyError):
    def __init__(self, message="Unable to parse the requirement: {line}", line=""):
        self.message = message.format(line=line)
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_INVALID_REQUIREMENT


class DatabaseFileNotFoundError(DatabaseFetchError):

    def __init__(self, db=None, message="Unable to find vulnerability database in {db}"):
        self.db = db
        self.message = message.format(db=db)
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_UNABLE_TO_LOAD_LOCAL_VULNERABILITY_DB


class InvalidCredentialError(DatabaseFetchError):

    def __init__(self, credential: Optional[str] = None, message="Your authentication credential{credential}is invalid. See {link}.", reason=None):
        self.credential = credential
        self.link = 'https://bit.ly/3OY2wEI'
        self.message = message.format(credential=f" '{self.credential}' ", link=self.link) if self.credential else message.format(credential=' ', link=self.link)
        info = f" Reason: {reason}"
        self.message = self.message + (info if reason else "")
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_INVALID_API_KEY

class NotVerifiedEmailError(SafetyError):
    def __init__(self, message="email is not verified"):
        self.message = message
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_EMAIL_NOT_VERIFIED

class TooManyRequestsError(DatabaseFetchError):

    def __init__(self, reason=None,
                 message="Too many requests."):
        info = f" Reason: {reason}"
        self.message = message + (info if reason else "")
        super().__init__(self.message)

    def get_exit_code(self):
        return EXIT_CODE_TOO_MANY_REQUESTS


class NetworkConnectionError(DatabaseFetchError):

    def __init__(self, message="Check your network connection, unable to reach the server."):
        self.message = message
        super().__init__(self.message)


class RequestTimeoutError(DatabaseFetchError):

    def __init__(self, message="Check your network connection, the request timed out."):
        self.message = message
        super().__init__(self.message)


class ServerError(DatabaseFetchError):

    def __init__(self, reason=None,
                 message="Sorry, something went wrong.\n" + "Safety CLI can not connect to the server.\n" +
                         "Our engineers are working quickly to resolve the issue."):
        info = f" Reason: {reason}"
        self.message = message + (info if reason else "")
        super().__init__(self.message)
