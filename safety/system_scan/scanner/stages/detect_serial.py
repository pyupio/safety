from typing import Iterable, Iterator, Protocol
from ..models import Candidate
from ..context import DetectContext
from ..models import Detection


class Detector(Protocol):
    """
    Detector protocol.
    """

    name: str

    def detect(
        self, candidate: Candidate, ctx: DetectContext
    ) -> Iterable[Detection]: ...


class DetectStageSerial:
    """
    Single-threaded detection stage.
    """

    name = "detect_serial"

    def __init__(
        self,
        detectors: list[Detector],
    ):
        self.detectors = detectors

    def run(
        self, items: Iterable[Candidate], ctx: DetectContext
    ) -> Iterator[Detection]:
        """
        Run detection stage.
        """
        for c in items:
            for det in self.detectors:
                yield from det.detect(c, ctx)
