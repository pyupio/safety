from enum import Enum, auto


class InterceptorType(Enum):
    UNIX_ALIAS = auto()
    WINDOWS_BAT = auto()
