from typing import Iterable, Iterator
from ..context import DetectContext
from ..models import Candidate
from ..sources import Source


class CandidatesStage:
    """
    Stage that merges multiple sources into a single Candidate stream.
    """

    name = "candidates"

    def __init__(self, sources: list[Source]):
        self.sources = sources

    def run(self, items: Iterable[None], ctx: DetectContext) -> Iterator[Candidate]:
        for src in self.sources:
            yield from src.iter_candidates()
