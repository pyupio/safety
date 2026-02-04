from typing import Generic, Protocol, TypeVar


T_contra = TypeVar("T_contra", contravariant=True)


class Sink(Protocol, Generic[T_contra]):
    def open(self, machine_id: str, hostname: str) -> str: ...
    def write(self, item: T_contra) -> None: ...
    def close(self, ok: bool) -> None: ...
