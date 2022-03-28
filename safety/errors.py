class DatabaseFetchError(Exception):
    pass


class DatabaseFileNotFoundError(DatabaseFetchError):
    pass


class InvalidKeyError(DatabaseFetchError):
    pass


class TooManyRequestsError(DatabaseFetchError):
    pass


class NetworkConnectionError(DatabaseFetchError):
    pass


class RequestTimeoutError(DatabaseFetchError):
    pass


class ServerError(DatabaseFetchError):
    pass

