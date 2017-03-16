class DatabaseFetchError(Exception):
    pass


class InvalidKeyError(DatabaseFetchError):
    pass
