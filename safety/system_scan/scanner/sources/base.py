from abc import ABC, abstractmethod
from typing import Iterator
from ..models import Candidate


class Source(ABC):
    """
    Base class for sources that generate candidates.
    """

    @abstractmethod
    def iter_candidates(self) -> Iterator[Candidate]:
        """
        Generate candidate objects.
        """
        pass
