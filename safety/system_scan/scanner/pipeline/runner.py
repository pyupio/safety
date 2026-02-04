from typing import Iterable, Iterator, Protocol, TypeVar, Generic, Any, Sequence

T_in = TypeVar("T_in", contravariant=True)
T_out = TypeVar("T_out", covariant=True)


class Stage(Protocol, Generic[T_in, T_out]):
    name: str

    def run(self, items: Iterable[T_in], ctx) -> Iterator[T_out]: ...


def run_pipeline(
    initial: Iterable[Any], stages: Sequence[Stage[Any, Any]], ctx
) -> Iterable[Any]:
    stream: Iterable[Any] = initial
    for st in stages:
        stream = st.run(stream, ctx)
    return stream
